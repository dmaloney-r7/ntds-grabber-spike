#include "ntds_common.h"
#include "ntds_jet.h"
#include "syskey.h"

void bytes_to_string(LPBYTE data, int length, LPSTR output);
void dump_account(struct ntdsAccount *userAccount);
void process_ntds(char *path);