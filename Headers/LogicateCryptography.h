#pragma once

#include "NetworkTypes.h"

class LGCrypto {
public:
	LGCrypto() = delete;

	static RSAKeys    GenerateRSAPair(int bits);
	static BYTESTRING RSADecrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
	static BYTESTRING RSAEncrypt(BYTESTRING data, RSA* key, BOOL isPrivateKey);
	static BOOL		  EncryptFileUsingRSAKey();
	static BOOL		  DeryptFileUsingRSAKey();
};
