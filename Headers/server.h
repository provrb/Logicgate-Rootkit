#ifndef _SERVER_INTERFACE_H_
#define _SERVER_INTERFACE_H_

#include "net_common.h"
#include "client.h"

using ClientData = std::tuple<Client, std::string, std::string>;

class ServerInterface
{
public:
	void          Start(); // Start a TCP server and start listening for UDP Requests

	BOOL          TCPSendMessageToClient(long cuid, ServerCommand req);
	BOOL          TCPSendMessageToClients(ServerCommand req);
	ClientRequest DecryptClientRequest(long cuid, BYTESTRING req);
	BYTESTRING    EncryptServerRequest(ServerRequest req);

	/*
		Send a message to a client usually
		after receiving a message from a client over udp.
		UDPMessage contains this class for the TCPServer
		to update the clients connection client-side.
	*/
	BOOL          UDPSendMessageToClient(long cuid, UDPMessage message);
	BOOL          AddToClientList();
	
	/*
		Accept a client connection to the tcp server.

		Use client class instead of client id because that is
		what is sent with the initial udp request and the client
		hasnt been added to the client list and cuid has not been
		generated for the client.
	*/
	BOOL          AcceptTCPConnection(Client clientToAccept);

	inline ClientData GetClientData(long cuid) {
		return GetClientList()[cuid];
	}

	inline std::unordered_map<long, ClientData> GetClientList() {
		return this->ClientList;
	}

protected:

	/*
		A thread to recv udp messages from
		clients wanting to connect.
	*/
	void           ListenForUDPMessages();

	/*
		Perform a received and encrypted udp request
		from a client.
	*/
	BOOL           PerformUDPRequest(BYTESTRING req);

	/*
		Generate an RSA public and private key 
		and format it as an std::pair
	*/
	std::pair<std::string, std::string> GenerateRSAPair();

	/*
		A dictionary with the clientId that contains
		Information about the connected client alongside its private and public
		uniquely generated rsa key for all connected clients
	*/
	std::unordered_map<long, ClientData> ClientList;

private:
	int sfd = -1; // server socket file descriptor
};

#endif // _SERVER_H_