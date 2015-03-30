// ntds1.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <process.h>
#include <Windows.h>
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
	JET_COLUMNDEF accountSID;
	JET_COLUMNDEF accountType;
	JET_COLUMNDEF accountExpiry;
	JET_COLUMNDEF encryptionKey;
	JET_COLUMNDEF lastLogon;
	JET_COLUMNDEF lmHash;
	JET_COLUMNDEF lmHistory;
	JET_COLUMNDEF logonCount;
	JET_COLUMNDEF ntHash;
	JET_COLUMNDEF ntHistory;
}ntdsColumns;

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

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTm590045", &accountColumns->accountName, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the samAccountName");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTr589970", &accountColumns->accountSID, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the SID");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTj590126", &accountColumns->accountType, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the Account Type");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTq589983", &accountColumns->accountExpiry, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the Account Expiration Date");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTq589983", &accountColumns->accountExpiry, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the Account Expiration Date");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTk590689", &accountColumns->encryptionKey, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the Password Encryption Key");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTq589876", &accountColumns->lastLogon, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the Last Logon Time");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTk589879", &accountColumns->lmHash, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the current LM hash");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTk589984", &accountColumns->lmHistory, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the LM hash history");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTj589993", &accountColumns->logonCount, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the logon count");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTk589914", &accountColumns->ntHash, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the current NT Hash");
		return columnError;
	}

	columnError = JetGetTableColumnInfo(ntdsState->jetSession, ntdsState->jetTable, "ATTk589918", &accountColumns->ntHistory, sizeof(JET_COLUMNDEF), JET_ColInfo);
	if (columnError != JET_errSuccess){
		puts("Error getting Column Definition for the NT Hash history");
		return columnError;
	}
	return JET_errSuccess;
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
		//Set up our column values here
		wchar_t accountName[255];
		unsigned char accountSID[255];
		DWORD accountType = 0;
		unsigned char accountExpiry[255];
		unsigned char encryptionKey[255];
		unsigned char lastLogon[255];
		unsigned char lmHash[255];
		unsigned char lmHistory[255];
		unsigned char logonCount[255];
		unsigned char ntHash[255];
		unsigned char ntHistory[255];
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
		readStatus = JetRetrieveColumn(ntdsState->jetSession, ntdsState->jetTable, accountColumns->accountName.columnid, &accountName, sizeof(accountName), &columnSize, 0, NULL);
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

int _tmain(int argc, TCHAR* argv[])
{
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

	read_table(ntdsState, accountColumns);

	return 0;
}

