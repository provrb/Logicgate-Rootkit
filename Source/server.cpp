#include "../Headers/server.h"

BOOL ServerInterface::ClientIsInClientList(long cuid) {
	return (std::get<AES_KEY>(GetClientData(cuid)) == "Client Doesn't Exist");
}

BOOL ServerInterface::AddToClientList(Client client) {
	long cuid = -1;
	
	// generate a cuid that isnt in use
	while ( cuid != -1 && IsCUIDInUse(cuid) )
		cuid = client.GenerateCUID();

	client.SetClientID(cuid);
	

}

BOOL ServerInterface::IsClientAlive(long cuid) {
	ClientData clientInfo = GetClientData(cuid);
	Client client = std::get<CLIENT_CLASS>(clientInfo);

	// Check if client is in ClientList and exists
	if ( !ClientIsInClientList(cuid) )
		return FALSE; // Client doesn't exist. Nothing returned from GetClientData

	if ( client.SocketReady(TCP) == FALSE )
		return FALSE; // socket not setup 

	// Check if client sends and receives ping
	if ( PingClient(cuid).responseCode != C_OK )
		return FALSE; // Client is dead

	return TRUE; // Client is alive
}

template <typename Data>
Data ServerInterface::DecryptClientData(BYTESTRING cipher, long cuid) {
	if ( !ClientIsInClientList(cuid) )
		return {};

	ClientData  clientInfo    = GetClientData(cuid);
	std::string decryptionKey = std::get<AES_KEY>(clientInfo);
	Data        decrypted     = NetCommon::DecryptInternetData<Data>(req, decryptionKey);
	
	return decrypted;
}

ClientRequest ServerInterface::DecryptClientRequest(long cuid, BYTESTRING req) {
	return DecryptClientData<ClientRequest>(req, cuid); // return decrypted clientRequest struct
}

ClientResponse ServerInterface::DecryptClientResponse(long cuid, BYTESTRING resp) {
	return DecryptClientData<ClientResponse>(resp, cuid);
}

BYTESTRING ServerInterface::EncryptServerRequest(ServerRequest req) {
	NET_BLOB blob = NetCommon::RequestToBlob(req, req.publicEncryptionKey);
	BYTESTRING cipher = NetCommon::AESEncryptBlob(blob);

	return cipher;
}

BOOL ServerInterface::IsCUIDInUse(long cuid) {
	try {
		ClientData data = GetClientList().at(cuid);
		Client     client = std::get<CLIENT_CLASS>(data);

		if ( !IsClientAlive(cuid) ) {
			if ( ClientIsInClientList(cuid) )
				RemoveClientFromClientList(cuid);
			
			return FALSE;
		}
	}
	catch ( const std::out_of_range& ) {
		return FALSE;
	}

	return TRUE;
}