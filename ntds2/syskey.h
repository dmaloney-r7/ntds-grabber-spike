#include "ntds_common.h"

BOOL get_syskey_component(HKEY lsaHandle, char subkeyName[255], unsigned char *tmpSysKey);
BOOL get_syskey(unsigned char *sysKey);