#include "ntds_common.h"
#include "decrypt.h"
#include <esent.h>
#pragma comment(lib, "esent")

struct jetState{
	TCHAR ntdsPath[255];
	JET_INSTANCE jetEngine;
	JET_SESID jetSession;
	JET_DBID jetDatabase;
	JET_TABLEID jetTable;
};

struct ntdsColumns{
	JET_COLUMNDEF accountName;
	JET_COLUMNDEF accountType;
	JET_COLUMNDEF accountExpiry;
	JET_COLUMNDEF accountDescription;
	JET_COLUMNDEF accountControl;
	JET_COLUMNDEF encryptionKey;
	JET_COLUMNDEF lastLogon;
	JET_COLUMNDEF lastPasswordChange;
	JET_COLUMNDEF lmHash;
	JET_COLUMNDEF lmHistory;
	JET_COLUMNDEF logonCount;
	JET_COLUMNDEF ntHash;
	JET_COLUMNDEF ntHistory;
	JET_COLUMNDEF accountSID;
};

struct ntdsAccount{
	wchar_t accountName[20];
	wchar_t accountDescription[1024];
	DWORD accountRID;
	BOOL accountDisabled;
	BOOL accountLocked;
	BOOL noPassword;
	BOOL passNoExpire;
	BOOL passExpired;
	int logonCount;
	int numNTHistory;
	int numLMHistory;
	char expiryDate[30];
	char logonDate[30];
	char logonTime[30];
	char passChangeDate[30];
	char passChangeTime[30];
	char lmHash[33];
	char ntHash[33];
	char lmHistory[792];
	char ntHistory[792];
	unsigned char accountSID[24];
};


// UserAccountControl Flags
#define NTDS_ACCOUNT_DISABLED         0x00000002
#define NTDS_ACCOUNT_LOCKED           0x00000010
#define NTDS_ACCOUNT_NO_PASS          0x00000020
#define NTDS_ACCOUNT_PASS_NO_EXPIRE   0x00010000
#define NTDS_ACCOUNT_PASS_EXPIRED     0x00800000

JET_ERR engine_shutdown(struct jetState *ntdsState);
JET_ERR engine_startup(struct jetState *ntdsState);
JET_ERR get_column_info(struct jetState *ntdsState, struct ntdsColumns *accountColumns);
JET_ERR get_PEK(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct encryptedPEK *pekEncrypted);
JET_ERR open_database(struct jetState *ntdsState);
JET_ERR read_table(struct jetState *ntdsState, struct ntdsColumns *accountColumns, struct decryptedPEK *pekDecrypted);