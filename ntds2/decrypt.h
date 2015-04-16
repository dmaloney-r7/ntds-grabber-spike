#include "ntds_common.h"
#include <wincrypt.h>

typedef struct{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char encryptedHash[16];
}encryptedHash;

typedef struct{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char pekData[36];
	unsigned char pekFinal[16];
}encryptedPEK;

typedef struct{
	unsigned char pekData[36];
	unsigned char pekKey[16];
}decryptedPEK;

