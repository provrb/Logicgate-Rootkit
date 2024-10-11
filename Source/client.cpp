#include "../../Headers/client.h"
#include "../../Headers/obfuscate.h"
#include "../../Headers/procutils.h"

BOOL Client::SocketReady(SocketTypes type) const {
	BOOL socketReady = FALSE;

	switch ( type ) {
	case UDP:
		socketReady = this->UDPSocket != INVALID_SOCKET;
		break;
	case TCP:
		socketReady = this->TCPSocket != INVALID_SOCKET;
		break;
	}

	return socketReady == TRUE;
}

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
	request.udp = this->UDPSocket;
	request.valid = TRUE;

	BOOL validServerResponse = UDPSendMessageToServer(request);
	if ( !validServerResponse )
		return FALSE;  

	// connect to tcp server
	this->TCPSocket = CreateSocket(AF_INET, SOCK_STREAM, 0);
	if ( this->TCPSocket == INVALID_SOCKET )
		return FALSE;

	int connect = ConnectSocket(this->TCPSocket, ( sockaddr* ) &this->ConnectedServer.addr, sizeof(this->ConnectedServer.addr));
	if ( connect == SOCKET_ERROR )
		return FALSE;

	// set everything now that we are connected to tcp server
	CloseSocket(this->UDPSocket); // no longer needed
	this->UDPSocket = INVALID_SOCKET;
	
	this->RSAPublicKey = GetPublicRSAKeyFromServer();
	CLIENT_DBG("Connected");
	return TRUE;
}

BIO* Client::GetPublicRSAKeyFromServer() {
	// receive the rsa public key
	BYTESTRING serialized;
	
	CLIENT_DBG("getting rsa pub key");
	
	BOOL success = NetCommon::ReceiveData(serialized, this->TCPSocket, TCP);
	if ( !success )
		return nullptr;
	
	CLIENT_DBG("got key");

	// the base64 encoded ras key
	std::string base64 = std::string(serialized.begin(), serialized.end());
	MessageBoxA(NULL, base64.c_str(), "b64", MB_OK);
	std::string bio = "";
	macaron::Base64::Decode(base64, bio);
	MessageBoxA(NULL, bio.c_str(), "bio", MB_OK);

	BIO* pub = NetCommon::GetBIOFromString(( char* ) bio.c_str(), bio.length());
	return pub;
}

BYTESTRING Client::EncryptClientRequest(ClientRequest req) const {
	BYTESTRING serialized = NetCommon::SerializeStruct(req);
	BYTESTRING buff = NetCommon::RSAEncryptStruct(serialized, this->RSAPublicKey);

	return buff;
}

ServerRequest Client::DecryptServerRequest(BYTESTRING req) {
	return NetCommon::DecryptInternetData<ServerRequest>(req, this->RSAPublicKey);
}

sockaddr_in Client::UDPRecvMessageFromServer(UDPResponse& out) {

	// decrypt the udp response and cast it to UDPResponse
	sockaddr_in outAddress = NetCommon::UDPRecvMessage(this->UDPSocket, out);
	 
	if ( out.isValid ) 
		this->ConnectedServer = out.TCPServer;

	return outAddress;
}
BOOL Client::UDPSendMessageToServer(ClientRequest message) {
	BOOL sent = NetCommon::UDPSendMessage(message, this->UDPSocket, this->UDPServerDetails.addr);
	if ( !sent ) 
		return FALSE;

	// return if the response from the server is valid
	UDPResponse response;
	UDPRecvMessageFromServer(response);
	
	return response.isValid;
}

BOOL Client::TCPSendMessageToServer(ClientMessage message) {
	return NetCommon::TCPSendMessage(message, this->TCPSocket);
}

BOOL Client::TCPSendEncryptedMessageToServer(ClientMessage message) {
	OutputDebugStringA("sending msg");
	return NetCommon::TCPSendEncryptedMessage(message, this->TCPSocket, this->RSAPublicKey);
}

BOOL Client::MakeServerRequest(ClientRequest request, BOOL udp) {
	return udp ? UDPSendMessageToServer(request) : TCPSendMessageToServer(request);
}

BOOL Client::Disconnect() {
	if ( !SocketReady(TCP) )
		return FALSE;

	int status = CloseSocket(this->TCPSocket);
	if ( status == SOCKET_ERROR ) {
		return FALSE;
	}

	return TRUE;
}

#endif