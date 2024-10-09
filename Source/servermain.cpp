#include <winsock2.h>
#include <ws2tcpip.h>
#include <iostream>
#include "../Headers/server.h"
#include <openssl/rsa.h>
#include <openssl/evp.h>

// Link with ws2_32.lib
#pragma comment(lib, "ws2_32.lib")
#define ADDR "logicgate-test.ddns.net"

int main() {
    ServerInterface server(5454, 4820); // make a tcp server on port 5454 and start it

    Server tcp = server.GetTCPServer();
    Server udp = server.GetUDPServer();
    server.StartServer(tcp);
    server.StartServer(udp);

    while ( 1 ) {
        std::this_thread::sleep_for(std::chrono::seconds(1)); // Simple wait to keep the main thread alive
    }

    return 0;
}
