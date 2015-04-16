#include "stdafx.h"
#include <stdio.h>
#include <string.h>
#include <wchar.h>
#include <process.h>
#include <Windows.h>
#pragma comment(lib, "Ws2_32.lib")


// UserAccountControl Flags
#define NTDS_ACCOUNT_DISABLED         0x00000002
#define NTDS_ACCOUNT_LOCKED           0x00000010
#define NTDS_ACCOUNT_NO_PASS          0x00000020
#define NTDS_ACCOUNT_PASS_NO_EXPIRE   0x00010000
#define NTDS_ACCOUNT_PASS_EXPIRED     0x00800000

#define BLANK_LM_HASH "aad3b435b51404eeaad3b435b51404ee"
#define BLANK_NT_HASH "31d6cfe0d16ae931b73c59d7e0c089c0"