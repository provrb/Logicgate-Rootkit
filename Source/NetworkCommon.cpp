#include "NetworkCommon.h"
#include "ProcessManager.h"

#include <vector>

#ifdef CLIENT_RELEASE
#pragma comment (lib, "ws2_32.lib")
#endif

void NetCommon::LoadWSAFunctions() {
    if ( WSAInitialized )
        return;

    if ( !DllsLoaded ) {
#ifdef SERVER_RELEASE
    Kernel32DLL = LoadLibraryA("kernel32.dll");
    NTDLL = LoadLibraryA("ntdll.dll");
    AdvApi32DLL = LoadLibraryA("advapi32.dll");
    DllsLoaded = TRUE;
#endif
    }

    // load winsock and kernel32 libraries

    HMODULE WINSOCK = ProcessManager::GetFunctionAddress<_LoadLibrary>(Kernel32DLL, std::string(HIDE("LoadLibraryA")))( (char*)HIDE("Ws2_32.dll") );

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

    WORD    version = MAKEWORD(2, 2);
    WSAData data = { 0 };

    if ( StartWSA(version, &data) == 0 ) {
        WSAInitialized = TRUE;
        CLIENT_DBG("init");
        std::cout << "initialized wsa and functions";
    }

    OutputDebugStringA("loaded");
}

BIO* NetCommon::BIODeepCopy(BIO* in) {
    BIO* copy = BIO_new(BIO_s_mem());
    BUF_MEM* buffer;

    BIO_get_mem_ptr(in, &buffer); // get everything used in 'in' bio
    BIO_write(copy, buffer->data, buffer->length); // copy all the memory from 'in' to 'copy'

    return copy;
}