#pragma once

#include "NetworkTypes.h"

class LGCrypto {
public:
	LGCrypto() = delete;

	static RSAKeys       GenerateRSAPair(int bits);
	static BYTESTRING    RSADecrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
	static BYTESTRING    RSAEncrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
	static RSA*		     RSAKeyFromString(std::string& s);
	static std::string   RSAKeyToString(RSA* key, BOOL isPrivateKey);
	static inline BOOL   GoodDecrypt(BYTESTRING d) { return ( d.size() != 0 ); }

	static BOOL		     EncryptFileUsingRSAKey();
	static BOOL		     DeryptFileUsingRSAKey();
};
