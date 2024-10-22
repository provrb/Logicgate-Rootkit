#pragma once

#include "NetworkTypes.h"

class LGCrypto {
public:
	LGCrypto(RSAKeys& keys)
		: m_CryptoSecrets(keys)
	{
	}

	static BYTESTRING RSADecrypt(BYTESTRING data, BIO* key, BOOL isPrivateKey);
	static BYTESTRING RSAEncrypt(BYTESTRING data, BIO* key, BOOL isPrivateKey);

#ifdef SERVER_RELEASE 
	// server usually uses private keys. default isPrivateKey is true
	BYTESTRING       RSADecrypt(BYTESTRING data, BOOL isPrivateKey=TRUE);
	BYTESTRING       RSAEncrypt(BYTESTRING data, BOOL isPrivateKey=TRUE);
# elif defined(CLIENT_RELEASE) 
	// client usually uses public keys. default isPrivateKey is false
	BYTESTRING       RSADecrypt(BYTESTRING data, BOOL isPrivateKey=FALSE);
	BYTESTRING       RSAEncrypt(BYTESTRING data, BOOL isPrivateKey=FALSE);
#endif

	BOOL		     EncryptFileUsingRSAKey();
	BOOL			 DecryptFileUsingRSAKey();
	inline BOOL		 IsPrivateKey(const std::string& rsaKey) const { return rsaKey == this->m_CryptoSecrets.strPrivateKey; }

private:
	RSAKeys m_CryptoSecrets = {};
};
