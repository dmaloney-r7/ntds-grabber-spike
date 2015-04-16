#include "ntds_common.h"
#include "decrypt.h"
#include <esent.h>
#pragma comment(lib, "esent")

typedef struct {
	TCHAR ntdsPath[255];
	JET_INSTANCE jetEngine;
	JET_SESID jetSession;
	JET_DBID jetDatabase;
	JET_TABLEID jetTable;
}jetState;

typedef struct {
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
}ntdsColumns;

typedef struct{
	wchar_t accountName[255];
	char expiryDate[255];
	char logonDate[255];
	char logonTime[255];
	char passChangeDate[255];
	char passChangeTime[255];
	wchar_t accountDescription[255];
	BOOL accountDisabled;
	BOOL accountLocked;
	BOOL noPassword;
	BOOL passNoExpire;
	BOOL passExpired;
	char lmHash[33];
	LPBYTE lmHistory;
	int logonCount;
	int numNTHistory;
	int numLMHistory;
	char ntHash[33];
	LPBYTE ntHistory;
	unsigned char accountSID[24];
	DWORD accountRID;
}ntdsAccount;

