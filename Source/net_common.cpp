#include "../Headers/net_common.h"
#include "../Headers/aes.hpp"
#include "../Headers/procutils.h"

#include <vector>

void NetCommon::LoadWSAFunctions() {
    if ( WSAInitialized )
        return;

    HMODULE kernel32 = ProcessUtilities::GetModHandle(ProcessUtilities::freqDLLS::kernel32); // load winsock
    ProcessUtilities::PPROCFN::_LoadLibrary load = ProcessUtilities::GetFunctionAddress<ProcessUtilities::PPROCFN::_LoadLibrary>(kernel32, std::string(HIDE("LoadLibraryA")));

    HMODULE WINSOCK = load(winsock32.c_str());

    // function pointers from winsock
    StartWSA = ProcessUtilities::GetFunctionAddress<_WSAStartup>(WINSOCK, std::string(HIDE("WSAStartup")));
    BindSocket = ProcessUtilities::GetFunctionAddress<_bind>(WINSOCK, std::string(HIDE("bind")));
    CloseSocket = ProcessUtilities::GetFunctionAddress<_closesocket>(WINSOCK, std::string(HIDE("closesocket")));
    CreateSocket = ProcessUtilities::GetFunctionAddress<_socket>(WINSOCK, std::string(HIDE("socket")));
    Receive = ProcessUtilities::GetFunctionAddress<_recv>(WINSOCK, std::string(HIDE("recv")));
    SendTo = ProcessUtilities::GetFunctionAddress<_sendto>(WINSOCK, std::string(HIDE("sendto")));
    ReceiveFrom = ProcessUtilities::GetFunctionAddress<_recvfrom>(WINSOCK, std::string(HIDE("recvfrom")));
    Send = ProcessUtilities::GetFunctionAddress<_send>(WINSOCK, std::string(HIDE("send")));
    CleanWSA = ProcessUtilities::GetFunctionAddress<_WSACleanup>(WINSOCK, std::string(HIDE("WSACleanup")));
    ConnectSocket = ProcessUtilities::GetFunctionAddress<_connect>(WINSOCK, std::string(HIDE("connect")));
    SocketListen = ProcessUtilities::GetFunctionAddress<_listen>(WINSOCK, std::string(HIDE("listen")));
    ShutdownSocket = ProcessUtilities::GetFunctionAddress<_shutdown>(WINSOCK, std::string(HIDE("shutdown")));
    AcceptOnSocket = ProcessUtilities::GetFunctionAddress<_accept>(WINSOCK, std::string(HIDE("accept")));

    WORD version = MAKEWORD(2, 2);
    WSAData data = { 0 };

    if ( StartWSA(version, &data) == 0 )
        WSAInitialized = TRUE;
}

//BYTESTRING NetCommon::ExtractIV(std::string key) {
//    BYTESTRING iv(16);
//    for ( int i = 0; i < 15; i++ )
//        iv.at(i) = key.at(i);
//
//    return iv;
//}

BYTESTRING NetCommon::SerializeBlob(NET_BLOB data) {
    BYTESTRING serialized;

    if ( data.cr.valid ) {
        serialized.resize(sizeof(ClientRequest));
        char* bytes = reinterpret_cast< char* >( &data.cr );
        std::copy(bytes, bytes + sizeof(ClientRequest), serialized.begin());
    }
    else if ( data.sr.valid ) {
        serialized.resize(sizeof(ServerRequest));
        char* bytes = reinterpret_cast< char* >( &data.sr );
        std::copy(bytes, bytes + sizeof(ServerRequest), serialized.begin());
    }
    else if ( data.udp.isValid ) {
        serialized.resize(sizeof(UDPResponse));
        char* bytes = reinterpret_cast< char* >( &data.udp );
        std::copy(bytes, bytes + sizeof(UDPResponse), serialized.begin());
    }

    return serialized;
}

BYTESTRING NetCommon::AESEncryptBlob(NET_BLOB data) {
    if ( IsBlobValid(data) == FALSE )
        return {};

    BYTESTRING req = SerializeBlob(data);
    BYTESTRING key = NetCommon::SerializeString(data.aesKey);

    Cipher::Aes<256> aes(key.data());
    aes.encrypt_block(req.data());

    return req;
}
