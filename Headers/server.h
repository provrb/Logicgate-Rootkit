#ifndef _SERVER_H_
#define _SERVER_H_

#include "net_types.h"
#include "net_common.h"
#include "client.h"

class ServerInterface
{
public:
	void Start(); // Start a TCP server and start listening for UDP Requests

	/*
	   A dictionary with the clientId that contains 
	   Information about the connected client for all
	   connected clients
	*/
	std::unordered_map<long, Client> clientList;

	BOOL TCPSendMessageToClient(long cuid, ServerCommand req);

	BOOL TCPSendMessageToClients(ServerCommand req);

	/*
		Send a message to a client usually
		after receiving a message from a client over udp.
		UDPMessage contains this class for the TCPServer
		to update the clients connection client-side.
	*/
	BOOL UDPSendMessageToClient(long cuid, UDPMessage message);

	BOOL AddToClientList();

protected:

	/*
		A thread to recv udp messages from
		clients wanting to connect.
	*/
	void ListenForUDPMessages();

	/*
		Perform a received and encrypted udp request
		from a client.
	*/
	BOOL PerformUDPRequest(BYTESTRING req);

};

#endif // _SERVER_H_