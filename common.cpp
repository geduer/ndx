#include "common.h"

unsigned int read_uint32(ULONG64 struct_addr, const char* struct_name, const char* field_name)
{
	unsigned int value;
	ULONG offset;

	value = 0;

	GetFieldOffset(struct_name, field_name, &offset);
	ReadMemory(struct_addr + offset, &value, sizeof(value), NULL);

	return value;
}

void split_args(struct ndx_args* args_info, PCSTR args)
{
	int i;
	size_t len;
	char* temp;
	char* next_str;

	i = 0;
	len = 0;
	next_str = 0;

	len = strnlen(args, MAX_ARGS_NUM * MAX_PATH);

	if (len >= MAX_ARGS_NUM * MAX_PATH) {
		args_info->argc = -1;
		return;
	}
	else if (len == 0) {
		args_info->argc = 0;
		return;
	}

	temp = strtok_s((char*)args, " ", &next_str);

	while (temp != NULL) {
		snprintf(args_info->argv[i], MAX_PATH, "%s", temp);

		i++;
		if (i >= MAX_ARGS_NUM) {
			break;
		}

		temp = strtok_s(NULL, " ", &next_str);
	}

	if (i < MAX_ARGS_NUM) {
		args_info->argc = i;
	}
	else {
		args_info->argc = MAX_ARGS_NUM;
	}

	if (i >= 1) {
		if (strnlen(args_info->argv[0], 22) >= 16 && strnlen(args_info->argv[0], 22) < 22) {
			args_info->has_addr = true;
			sscanf_s(args_info->argv[0], "%llx", &args_info->addr);
		}
		else {
			goto TAG_NO_ADDR_INPUT;
		}
	}
	else {
	TAG_NO_ADDR_INPUT:
		args_info->has_addr = false;
		args_info->addr = 0;
	}

	return;
}
