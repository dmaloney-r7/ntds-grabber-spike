// ntds1.cpp : Defines the entry point for the console application.
//

#include "ntds2.h"

void bytes_to_string(LPBYTE data, int length, LPSTR output){
	for (int i = 0; i < length; i++){
		sprintf(output + (i << 1), "%02X", ((LPBYTE)data)[i]);
	}
}

void dump_account(ntdsAccount *userAccount){
	puts("=============================================");
	wprintf(L"%s\n",userAccount->accountDescription);
	wprintf(L"%s:%d:", userAccount->accountName, userAccount->accountRID);
	printf("%s:%s\n",userAccount->lmHash,userAccount->ntHash);
	printf("Account Has Logged on %d time(s)\n", userAccount->logonCount);
	printf("Last Logon Time: %s on %s\n", userAccount->logonTime, userAccount->logonDate);
	printf("Account Expires: %s\n", userAccount->expiryDate);
	printf("Password was last changed: %s on %s\n", userAccount->passChangeTime, userAccount->passChangeDate);
	if (userAccount->noPassword){
		puts(" * Account does not require a password to logon!");
	}
	if (userAccount->passExpired){
		puts(" * Account password expired");
	}
	if (userAccount->accountDisabled){
		puts(" * Account is disabled");
	}
	if (userAccount->accountLocked){
		puts(" * Account is locked out");
	}
	if (userAccount->passNoExpire){
		puts(" * Account password never expires");
	}
	if (userAccount->ntHistory != NULL){
		puts("Historical Hashes:\n");
		LPBYTE ntReadMarker = userAccount->ntHistory;
		LPBYTE lmReadMarker = userAccount->lmHistory;
		for (int i = 0; i < userAccount->numNTHistory; i++){
			char ntHistHash[33];
			char lmHistHash[33];
			strncpy(ntHistHash, ntReadMarker, 33);
			if (lmReadMarker == NULL){
				strncpy(lmHistHash, BLANK_LM_HASH, 33);
			}
			else {
				strncpy(lmHistHash, lmReadMarker, 33);
			}
			wprintf(L"%s:%d:", userAccount->accountName, userAccount->accountRID);
			printf("%s:%s\n", lmHistHash, ntHistHash);
			ntReadMarker = ntReadMarker + 33;
			lmReadMarker = lmReadMarker + 33;
		}
	}
}

int _tmain(int argc, TCHAR* argv[])
{
	unsigned char sysKey[17];
	get_syskey(sysKey);

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
		exit(2);
	}
	_tcsncat(commandString, ntdsState->ntdsPath, 255);
	_putts(commandString);
	// Call the ESENTUTL utility on our NTDS.dit file
	_tsystem(commandString);
	JET_ERR startupStatus = engine_startup(ntdsState);
	if (startupStatus != JET_errSuccess){
		exit(startupStatus);
	}
	// Start a Session in the Jet Instance
	JET_ERR sessionStatus = JetBeginSession(ntdsState->jetEngine, &ntdsState->jetSession, NULL, NULL);
	if (sessionStatus != JET_errSuccess){
		exit(sessionStatus);
	}
	JET_ERR openStatus = open_database(ntdsState);
	if (openStatus != JET_errSuccess){
		exit(openStatus);
	}
	JET_ERR tableStatus = JetOpenTable(ntdsState->jetSession, ntdsState->jetDatabase, "datatable", NULL, 0, JET_bitTableReadOnly | JET_bitTableSequential, &ntdsState->jetTable);
	if (tableStatus != JET_errSuccess){
		exit(tableStatus);
	}
	JET_ERR columnStatus = get_column_info(ntdsState, accountColumns);
	if (columnStatus != JET_errSuccess){
		exit(columnStatus);
	}
	JET_ERR pekStatus;
	encryptedPEK *pekEncrypted = malloc(sizeof(encryptedPEK));
	decryptedPEK *pekDecrypted = malloc(sizeof(decryptedPEK));
	memset(pekEncrypted, 0, sizeof(encryptedPEK));
	memset(pekDecrypted, 0, sizeof(decryptedPEK));

	pekStatus = get_PEK(ntdsState, accountColumns,pekEncrypted);
	if (pekStatus != JET_errSuccess){
		exit(pekStatus);
	}
	BOOL decpekstatus = decrypt_PEK(sysKey, pekEncrypted, pekDecrypted);
	read_table(ntdsState, accountColumns, pekDecrypted);
	engine_shutdown(ntdsState);
	return 0;
}

