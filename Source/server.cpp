#include "../Headers/server.h"

ClientRequest ServerInterface::DecryptClientRequest(long cuid, BYTESTRING req) {

	ClientData clientInfo = GetClientData(cuid);
	Client     client     = std::get<0>(clientInfo);
	if ( !client.SocketReady(TCP) ) // Invalid client
		return {};

	std::string   decryptionKey = std::get<2>(clientInfo); // RSA Public Key. Used as AES Key when sending requests over sockets.
	ClientRequest clientReq     = NetCommon::DecryptInternetData<ClientRequest>(req, decryptionKey);

	return clientReq; // return decrypted clientRequest struct
}

BYTESTRING ServerInterface::EncryptServerRequest(ServerRequest req) {
	NET_BLOB blob = NetCommon::RequestToBlob(req, req.publicEncryptionKey);
	BYTESTRING cipher = NetCommon::AESEncryptBlob(blob);
	Client c;
	return cipher;


}