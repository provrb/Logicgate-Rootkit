#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "../Headers/server.h"

// Link with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")
#define ADDR "logicgate-test.ddns.net"

int main() {
    SOCKET ClientSocket = INVALID_SOCKET;
    struct sockaddr_in serverAddr;

    ServerInterface server(SocketTypes::TCP, 5454);

    // Bind the socket

    // Listen on the socket for incoming connections

    SOCKET ListenSocket = server.GetServerDetails().sfd;

    // Accept a client socket
    ClientSocket = accept(ListenSocket, nullptr, nullptr);
    if ( ClientSocket == INVALID_SOCKET ) {
        std::cerr << "Accept failed: " << WSAGetLastError() << std::endl;
        closesocket(ListenSocket);
        WSACleanup();
        return 1;
    }

    std::cout << "Client connected!" << std::endl;

    // Cleanup
    closesocket(ClientSocket);
    closesocket(ListenSocket);
    WSACleanup();
    return 0;
}
