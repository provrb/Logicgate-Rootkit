#include "ServerInterface.h"

#pragma comment(lib, "ws2_32.lib")

int main() {
    ServerInterface server(5454, 4820); // make a tcp server on port 5454 and start it
    
    Server tcp = server.GetTCPServer();
    Server udp = server.GetUDPServer();

    server.StartServer(tcp);
    server.StartServer(udp);

    while ( 1 ) {
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    return 0;
}


// Encrypting and decrypting with aes
/*
    std::string toEncrypt = "hello this is ethans message!";
    BYTESTRING bytestring = Serialization::SerializeString(toEncrypt);

    BYTESTRING key = LGCrypto::Generate256AESKey();
    std::cout << "got key!" << key.data() << std::endl;

    BYTESTRING iv = LGCrypto::GenerateAESIV();
    std::cout << "got iv!" << iv.data() << std::endl;

    BYTESTRING cipher = LGCrypto::AESEncrypt(bytestring, key, iv);
    std::cout << "encrypted : " << cipher.data() << std::endl;

    BYTESTRING decipherbytestring = LGCrypto::AESDecrypt(cipher, key, iv);
    std::string decipher = Serialization::BytestringToString(decipherbytestring);
    std::cout << "decrypted : " << decipher << std::endl;
*/


// Using 'OpenProcessAsImposter' to save output to a string
/*
    std::wstring        wstr = L"systeminfo";

    char* s = new char;

    ProcessManager pm;
    pm.OpenProcessAsImposter(
        pm.GetTrustedInstallerToken(),
        NULL,
        nullptr,
        wstr.data(),
        CREATE_NO_WINDOW,
        NULL,
        NULL,
        true,
        s
    );

    std::cout << s << std::endl;
*/

