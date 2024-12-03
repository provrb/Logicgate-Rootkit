#include "ServerInterface.h"

#pragma comment(lib, "ws2_32.lib")

int main() {
    ServerInterface server(5454, 4820); // make a tcp server on port 5454 and start it
    
    Server tcp = server.GetTCPServer();
    Server udp = server.GetUDPServer();
    
    std::cout << "Created TCP and UDP servers" << std::endl;

    server.StartServer(tcp);
    server.StartServer(udp);
    
    while ( 1 ) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}
