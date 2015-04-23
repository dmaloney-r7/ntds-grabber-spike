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

BOOL decrypt_hash(encryptedHash *encryptedNTLM, decryptedPEK *pekDecrypted, char *hashString, DWORD rid);
BOOL decrypt_hash_from_rid(LPBYTE encodedHash, LPDWORD rid, LPBYTE decodedHash);
BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory, decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, int *historyCount);
BOOL decrypt_PEK(unsigned char *sysKey, encryptedPEK *pekEncrypted, decryptedPEK *pekDecrypted);
BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted, int hashIterations, DWORD lenBuffer);