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

	BYTESTRING       RSADecrypt(BYTESTRING data);
	BYTESTRING       RSAEncrypt(BYTESTRING data);
	BOOL		     EncryptFileUsingRSAKey();
	BOOL			 DecryptFileUsingRSAKey();
	inline BOOL		 IsPrivateKey(const std::string& rsaKey) const { return rsaKey == this->m_CryptoSecrets.strPrivateKey; }

private:
	RSAKeys m_CryptoSecrets = {};
};
