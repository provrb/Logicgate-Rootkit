#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "../Headers/server.h"

// Link with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")
#define ADDR "logicgate-test.ddns.net"

int main() {
    struct sockaddr_in serverAddr;

    ServerInterface server(SocketTypes::TCP, 5454);

    // Accept a client socket
    SOCKET s = accept(server.GetServerDetails().sfd, nullptr, nullptr);
    if ( s != INVALID_SOCKET )
        std::cout << "Client connected!" << std::endl;

    return 0;
}
