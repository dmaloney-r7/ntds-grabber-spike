#include "ntds_common.h"
#include <wincrypt.h>

struct encryptedHash{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char encryptedHash[16];
};

struct encryptedPEK{
	unsigned char header[8];
	unsigned char keyMaterial[16];
	unsigned char pekData[36];
	unsigned char pekFinal[16];
};

struct decryptedPEK{
	unsigned char pekData[36];
	unsigned char pekKey[16];
};

BOOL decrypt_hash(struct encryptedHash *encryptedNTLM, struct decryptedPEK *pekDecrypted, char *hashString, DWORD rid);
BOOL decrypt_hash_from_rid(LPBYTE encodedHash, LPDWORD rid, LPBYTE decodedHash);
BOOL decrypt_hash_history(LPBYTE encHashHistory, size_t sizeHistory, struct decryptedPEK *pekDecrypted, DWORD rid, char *accountHistory, int *historyCount);
BOOL decrypt_PEK(unsigned char *sysKey, struct encryptedPEK *pekEncrypted, struct decryptedPEK *pekDecrypted);
BOOL decrypt_rc4(unsigned char *key1, unsigned char *key2, LPBYTE encrypted, int hashIterations, DWORD lenBuffer);