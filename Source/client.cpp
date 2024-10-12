#include "../Headers/client.h"
#include "../Headers/obfuscate.h"
#include "../Headers/procutils.h"
#include "../Headers/serialization.h"

#ifdef CLIENT_RELEASE

Client::Client() {
	NetCommon::LoadWSAFunctions();

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

BOOL Client::Connect() {
	// make request to udp server
	this->UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( this->UDPSocket == INVALID_SOCKET )
		return FALSE;

	ClientRequest request = {};
	request.action = ClientRequest::Action::CONNECT_CLIENT;
	request.udp    = this->UDPSocket;
	request.valid  = TRUE;

	BOOL validServerResponse = SendMessageToServer(this->UDPServerDetails, request, this->UDPServerDetails.addr);
	if ( !validServerResponse )
		return FALSE;  

	CLIENT_DBG("sent the request...");

	UDPResponse response;
	sockaddr_in serverAddr;
	BOOL received = ReceiveMessageFromServer(this->UDPServerDetails, response, serverAddr);
	if ( !received )
		return FALSE;

	CLIENT_DBG("received a message from the server..");

	this->UDPServerDetails.addr = serverAddr;
	this->TCPServerDetails = response.TCPServer;

	// connect to tcp server
	this->TCPSocket = CreateSocket(AF_INET, SOCK_STREAM, 0);
	if ( this->TCPSocket == INVALID_SOCKET )
		return FALSE;

	int connect = ConnectSocket(this->TCPSocket, ( sockaddr* ) &this->TCPServerDetails.addr, sizeof(this->TCPServerDetails.addr));
	if ( connect == SOCKET_ERROR )
		return FALSE;
	
	RSAKeys key = RSAKeys(GetPublicRSAKeyFromServer(), nullptr);
	this->SetEncryptionKeys(key);

	CLIENT_DBG("Connected");
	return TRUE;
}

BIO* Client::GetPublicRSAKeyFromServer() {
	// receive the rsa public key
	BYTESTRING serialized;
		
	BOOL success = NetCommon::ReceiveData(serialized, this->TCPSocket, TCP);
	if ( !success )
		return nullptr;
	
	// the base64 encoded ras key
	std::string base64 = Serialization::BytestringToString(serialized);
	std::string bio = "";
	macaron::Base64::Decode(base64, bio);

	BIO* pub = NetCommon::GetBIOFromString(( char* ) bio.c_str(), bio.length());
	return pub;
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
	if ( dest.type == SOCK_STREAM ) // tcp
		return NetCommon::TransmitData(message, this->TCPSocket, TCP, NetCommon::_default, TRUE, this->Secrets.publicKey);
	else if ( dest.type == SOCK_DGRAM ) // udp
		return NetCommon::TransmitData(message, this->UDPSocket, UDP, NetCommon::_default, TRUE, this->Secrets.publicKey);

	return FALSE;
}

BOOL Client::Disconnect() {
	int status = CloseSocket(this->TCPSocket);
	if ( status == SOCKET_ERROR ) {
		return FALSE;
	}

	return TRUE;
}

#endif