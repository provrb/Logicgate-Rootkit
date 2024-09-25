#include "../../Headers/client.h"
#include "../../Headers/obfuscate.h"
#include "../../Headers/procutils.h"

//#include <openssl/evp.h>
//#include <openssl/aes.h>


Client::Client() {
	NetCommon::LoadWSAFunctions();
}

Client::~Client() {
	this->Disconnect(); // disconnect incase the socket is still connected

	CleanWSA();
	ProcessUtilities::FreeUsedLibrary(winsock32);
}
// TODO: CHANGE ADDR TO SERVER DNS

BOOL Client::Connect() {

	// make request to udp server
	this->UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( this->UDPSocket == INVALID_SOCKET )
		return FALSE;

	ClientRequest request = {};
	request.action = ClientRequest::Action::CONNECT_CLIENT;
	request.client = reinterpret_cast<void*>(this);

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

	return TRUE;
}

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

BYTESTRING Client::EncryptClientRequest(ClientRequest req) const {
	NET_BLOB blob = NetCommon::RequestToBlob(req, this->EncryptionKey);
	BYTESTRING buff = NetCommon::AESEncryptBlob(blob);

	return buff;
}

ServerRequest Client::DecryptServerRequest(BYTESTRING req) {
	return NetCommon::DecryptInternetData<ServerRequest>(req, this->EncryptionKey);
}

UDPResponse Client::UDPRecvMessageFromServer() {
	BYTESTRING responseBuffer;
	responseBuffer.resize(1000);

	int received = ReceiveFrom(this->UDPSocket, reinterpret_cast< char* >( responseBuffer.data() ), sizeof(responseBuffer), 0, NULL, NULL);
	if ( received == SOCKET_ERROR )
		return {};

	// decrypt the udp response and cast it to UDPResponse
	UDPResponse response = NetCommon::DecryptInternetData<UDPResponse>(responseBuffer, this->EncryptionKey);
	if ( response.isValid ) this->ConnectedServer = response.TCPServer;

	return response;
}

BOOL Client::UDPSendMessageToServer(ClientMessage message) {
	if ( !SocketReady(UDP) )
		return FALSE;

	BYTESTRING encrypted = EncryptClientRequest(message);

	int sent = SendTo(this->UDPSocket, reinterpret_cast<char*>(encrypted.data()), sizeof(encrypted.size()), 0, NULL, NULL);
	if ( sent == SOCKET_ERROR )
		return FALSE;

	return UDPRecvMessageFromServer().isValid;
}

BOOL Client::TCPSendMessageToServer(ClientMessage message) {
	if ( !SocketReady(TCP) ) 
		return FALSE;

	BYTESTRING encryptedRequest = EncryptClientRequest(message);

	int sent = Send(this->TCPSocket, reinterpret_cast< char* >( encryptedRequest.data() ), encryptedRequest.size(), 0);
	if ( sent == SOCKET_ERROR )
		return FALSE;

	return TRUE;
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