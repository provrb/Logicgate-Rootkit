#include "net_common.h"
#include "procutils.h"

#include <vector>
#include <openssl/err.h>

void NetCommon::LoadWSAFunctions() {
    using namespace ProcessUtilities;

    if ( WSAInitialized )
        return;

    // load winsock and kernel32 libraries
    HMODULE kernel32 = GetModHandle(freqDLLS::kernel32);
    PPROCFN::_LoadLibrary load = GetFunctionAddress<PPROCFN::_LoadLibrary>(kernel32, std::string(HIDE("LoadLibraryA")));
    HMODULE WINSOCK = load(winsock32.c_str());

    // function pointers from winsock
    StartWSA           = GetFunctionAddress<_WSAStartup>(WINSOCK, std::string(HIDE("WSAStartup")));
    BindSocket         = GetFunctionAddress<_bind>(WINSOCK, std::string(HIDE("bind")));
    CloseSocket        = GetFunctionAddress<_closesocket>(WINSOCK, std::string(HIDE("closesocket")));
    CreateSocket       = GetFunctionAddress<_socket>(WINSOCK, std::string(HIDE("socket")));
    Receive            = GetFunctionAddress<_recv>(WINSOCK, std::string(HIDE("recv")));
    SendTo             = GetFunctionAddress<_sendto>(WINSOCK, std::string(HIDE("sendto")));
    ReceiveFrom        = GetFunctionAddress<_recvfrom>(WINSOCK, std::string(HIDE("recvfrom")));
    Send               = GetFunctionAddress<_send>(WINSOCK, std::string(HIDE("send")));
    CleanWSA           = GetFunctionAddress<_WSACleanup>(WINSOCK, std::string(HIDE("WSACleanup")));
    ConnectSocket      = GetFunctionAddress<_connect>(WINSOCK, std::string(HIDE("connect")));
    SocketListen       = GetFunctionAddress<_listen>(WINSOCK, std::string(HIDE("listen")));
    ShutdownSocket     = GetFunctionAddress<_shutdown>(WINSOCK, std::string(HIDE("shutdown")));
    AcceptOnSocket     = GetFunctionAddress<_accept>(WINSOCK, std::string(HIDE("accept")));
    HostToNetworkShort = GetFunctionAddress<_htons>(WINSOCK, std::string(HIDE("htons")));
    InternetAddress    = GetFunctionAddress<_inet_addr>(WINSOCK, std::string(HIDE("inet_addr")));
    GetHostByName      = GetFunctionAddress<_gethostbyname>(WINSOCK, std::string(HIDE("gethostbyname")));
    HostToNetworkLong  = GetFunctionAddress<_htonl>(WINSOCK, std::string(HIDE("htonl")));
    NetworkToHostLong  = GetFunctionAddress<_ntohl>(WINSOCK, std::string(HIDE("ntohl")));

    WORD    version = MAKEWORD(2, 2);
    WSAData data = { 0 };

    if ( StartWSA(version, &data) == 0 )
        WSAInitialized = TRUE;
}

BIO* NetCommon::BIODeepCopy(BIO* in) {
    BIO* copy = BIO_new(BIO_s_mem());
    BUF_MEM* buffer;

    BIO_get_mem_ptr(in, &buffer); // get everything used in 'in' bio
    BIO_write(copy, buffer->data, buffer->length); // copy all the memory from 'in' to 'copy'

    return copy;
}

BYTESTRING NetCommon::RSADecryptStruct(BYTESTRING data, BIO* bio, BOOL privateKey) {
    BIO* copied = NetCommon::BIODeepCopy(bio);

    EVP_PKEY* priv = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
    if ( !priv ) {
        std::cout << "bad key\n";
        return {};
    }

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

BYTESTRING NetCommon::RSAEncryptStruct(BYTESTRING data, BIO* bio, BOOL privateKey) {
    BIO* copied = BIODeepCopy(bio);
    EVP_PKEY* pub = privateKey ? PEM_read_bio_PrivateKey(copied, nullptr, nullptr, nullptr) : PEM_read_bio_PUBKEY(copied, nullptr, nullptr, nullptr);
    if ( !pub )
        return {};

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