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
	JET_COLUMNDEF encryptionKey;
	JET_COLUMNDEF lmHash;
	JET_COLUMNDEF lmHistory;
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

	return 0;
}

