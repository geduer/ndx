#include "common.h"

#define VIEW_CMD_USAGE	-1

void print_arena_help_info(void)
{
	dprintf(
		"\n----------------------------------------\n"

		"arena  : \n"
		"usage  : !arena [help] <address> [flag]\n"

		"\nhelp tag list ->\n"
		"\t--help / -h / -?\n"

		"----------------------------------------\n"
	);

	return;
}

void print_addr_help_info(void)
{
	dprintf(
		""
	);

	return;
}

void print_dmesg_help_info(void)
{
	dprintf(
		"\n----------------------------------------\n"

		"!dmesg   : when debugging the Linux kernel, use the !dmesg command to view the dmesg information\n"
		"usage    : !dmesg [help] [flag]\n"

		"\nhelp tag list ->\n"
		"\t--help / -h / -?\n"

		"\nflags list ->\n"
		"\t{file path}     : specify the local path of the dmesg file to decode\n"
		"\tdefault         : decode based on memory\n"

		"\nexample :\n"
		"\t!dmesg --help\n"
		"\t!dmesg d:/linux/dmesg_info/dmesg_20211015.txt\n"

		"----------------------------------------\n"
	);
}

void print_slab_help_info(void)
{
	dprintf(
		"\n----------------------------------------\n"

		"!slab  : when debugging the Linux kernel, view the slab allocator through the !slab command\n"
		"usage  : !slab [help] [flag]\n"

		"\nhelp tag list ->\n"
		"\t--help / -h / -?\n"

		"\nflags list ->\n"
		"\t-s      : sorts by individual object size\n"
		"\t-n      : sorts by the number of objects\n"
		"\t-t      : sorts by the total size of all objects\n"
		"\tdefault : do not sort\n"

		"\nexample :\n"
		"\t!slab --help\n"
		"\t!slab -s\n"

		"----------------------------------------\n"
	);

	return;
}

void print_lxp_help_info(void)
{
	dprintf(
		"\n----------------------------------------\n"

		"!lxp   : when debugging the Linux kernel, view the process information via the !lxp command\n"
		"usage  : !lxp [help] <address> [flag] [filter]\n"
		"\thelp       : view lxp's help information\n"
		"\taddress    : task_struct address\n"
		"\tflag       : select the type of information to display\n"
		"\tfilter     : filter process name\n"

		"\nhelp cmd list :\n"
		"\t--help / -h / -?\n"

		"\nflags list :\n"
		"\t0    : displays simple information about the process [default]\n"
		"\t1    : displays basic information about the process\n"

		"\nfilter optins :\n"
		"\tdefault : if the filter is empty, one process is listed by default\n"
		"\t0       : without filtering, lists all processes\n"
		"\t-n{x}   : dislays the process named x\n"
		"\t-c{y}   : limit the number of listed processes to y\n"

		"\nexample :\n"
		"\t!lxp --help\n"
		"\t!lxp 0xffffff9f63ff8000 1 -nswapper\n"
		"\t!lxp 0 -c15\n"

		"----------------------------------------\n"
	);

	return;
}

int print_cmd_help_info(struct ndx_args* args_info)
{
	int ret;

	ret = 0;

	if (args_info->argc < 0
		|| (strncmp(args_info->argv[0], "--help", MAX_ARG_LEN) == 0)
		|| (strncmp(args_info->argv[0], "-h", MAX_ARG_LEN) == 0)
		|| (strncmp(args_info->argv[0], "-?", MAX_ARG_LEN) == 0)) {

		return VIEW_CMD_USAGE;
	}

	return ret;
}
