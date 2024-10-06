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

	return TRUE;
}

BYTESTRING Client::EncryptClientRequest(ClientRequest req) const {
	BYTESTRING serialized = NetCommon::SerializeStruct(req);
	BYTESTRING buff = NetCommon::AESEncryptStruct(serialized, this->AESEncryptionKey);

	return buff;
}

ServerRequest Client::DecryptServerRequest(BYTESTRING req) {
	return NetCommon::DecryptInternetData<ServerRequest>(req, this->AESEncryptionKey);
}

UDPResponse Client::UDPRecvMessageFromServer() {
	BYTESTRING responseBuffer(sizeof(UDPResponse));

	int received = ReceiveFrom(this->UDPSocket, 
		(char*)responseBuffer.data(),
		responseBuffer.size(),
		0,
		NULL,
		NULL
	);

	if ( received == SOCKET_ERROR )
		return {};

	// decrypt the udp response and cast it to UDPResponse
	UDPResponse response = NetCommon::DeserializeToStruct<UDPResponse>(responseBuffer);
	if ( response.isValid ) 
		this->ConnectedServer = response.TCPServer;

	return response;
}
BOOL Client::UDPSendMessageToServer(ClientRequest message) {
	if ( !SocketReady(UDP) )
		return FALSE;
	
	BYTESTRING serialized = NetCommon::SerializeStruct(message);

	int sent = SendTo(this->UDPSocket, 
		(char*)serialized.data(), 
		serialized.size(),
		0,
		(sockaddr*)&this->UDPServerDetails.addr,
		sizeof(this->UDPServerDetails)
	);

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

#endif