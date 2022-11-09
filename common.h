#ifndef __NDX_COMMON_H__

#define __NDX_COMMON_H__

#include "dbgexts.h"
#include <wdbgexts.h>
#include <dbgeng.h>
#include <dbghelp.h>

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <extsfns.h>

#define MAX_ARGS_NUM		3
#define MAX_ARG_LEN		26

typedef struct ndx_args {
	bool has_addr;
	ULONG64 addr;
	int argc;
	char argv[MAX_ARGS_NUM][MAX_PATH];
} ndx_args;

void split_args(struct ndx_args* args_info, PCSTR args);
unsigned int read_uint32(ULONG64 struct_addr, const char* struct_name, const char* field_name);

#endif
