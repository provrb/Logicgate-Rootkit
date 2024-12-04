#include "ServerInterface.h"

#include <csignal>

#pragma comment(lib, "ws2_32.lib")

bool abortApp = false;

void SignalHandler(int signal) {
    abortApp = true;
}

int main() {
    ServerInterface server(5454, 4820); // make a tcp server on port 5454 and start it
    
    signal(SIGINT, SignalHandler);

    Server tcp = server.GetTCPServer();
    Server udp = server.GetUDPServer();
    
    std::cout << "Created TCP and UDP servers" << std::endl;

    server.StartServer(tcp);
    server.StartServer(udp);

    while ( 1 ) {
        if ( abortApp ) {
            server.~ServerInterface();
            return 0;
        }
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    system("cls");

    return 0;
}
