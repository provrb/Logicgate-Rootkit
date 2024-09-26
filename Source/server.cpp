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

	return cipher;
}

BOOL ServerInterface::IsCUIDInUse(long cuid) {
	try {
		ClientData data = GetClientList().at(cuid);
		Client     client = std::get<0>(data);

		// Check if the client was connected to tcp
		if ( !client.SocketReady(TCP) ) {
			return FALSE;
		} else {
			// client has a valid tcp socket on the server.
			// the question is, are they still connected to the tcp server?

			// ping client
			ClientResponse pingResult = PingClient(cuid);
			if ( pingResult.responseCode == C_ERROR ) {
				// dead client
				RemoveClientFromClientList(cuid);
				return FALSE;
			}
		}
	}
	catch ( const std::out_of_range& ) {
		return FALSE;
	}

	return TRUE;
}