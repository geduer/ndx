#include "common.h"
#include "xhelp.h"
#include "lxp.h"
#include "slab.h"
#include "dmesg.h"
// #include "addr.h"

#define KDEXT_64BIT

EXT_API_VERSION	ApiVersion =
{
	3,
	0,
	EXT_API_VERSION_NUMBER64,
	6
};

WINDBG_EXTENSION_APIS ExtensionApis;

ULONG64	SavedMajorVersion;
ULONG64	SavedMinorVersion;

/*
 *	function WinDbgExtensionDllInit must be exported
 *	function address table	->	lpExtensionApis£»
 *	address exists within a global variable
 */
VOID WinDbgExtensionDllInit(PWINDBG_EXTENSION_APIS lpExtensionApis, USHORT MajorVersion, USHORT MinorVersion)
{
	ExtensionApis = *lpExtensionApis;

	SavedMajorVersion = MajorVersion;
	SavedMinorVersion = MinorVersion;

	return;
}

/*
 *	function ExtensionApiVersion must be exported
 *	return EXT_API_VERSION_NUMBER64£¬64-bit addresses for api identification£»
 *	need KDEXT_64BIT ExtensionApis
 */
LPEXT_API_VERSION ExtensionApiVersion(VOID)
{
	return &ApiVersion;
}

VOID CheckVersion(VOID)
{
	return;
}

DECLARE_API(lxp)
{
	int ret;
	ULONG64 task_addr;
	ndx_args lxp_args;
	ndx_lxp_option lxp_option;

	task_addr = 0;
	lxp_args = { 0 };
	lxp_option = { 0 };

	split_args(&lxp_args, args);
	get_lxp_option(&lxp_args, &lxp_option);

	ret = print_cmd_help_info(&lxp_args);

	if (ret != 0) {
		goto TAG_HELP;
	}

	if (lxp_args.has_addr == true) {
		task_addr = lxp_args.addr;
	}
	else {
		GetExpressionEx("lk!init_task", &task_addr, NULL);
	}

	switch (lxp_option.flag) {
	case 100:
		show_task_simple_info(task_addr, &lxp_option);
		break;
	case 101:
		show_task_simple_info(task_addr, &lxp_option);
		break;
	case 102:
		show_task_base_info(task_addr, &lxp_option);
		break;
	default:
	TAG_HELP:
		print_lxp_help_info();

		break;
	}

	return;
}

DECLARE_API(slab)
{
	int ret;
	ULONG64 slab_caches_addr, list_head_addr;
	ULONG offset;
	ndx_args slab_args;

	list_head_addr = 0;
	slab_args = { 0 };

	split_args(&slab_args, args);

	ret = print_cmd_help_info(&slab_args);

	if (ret != 0) {
		goto TAG_HELP;
	}

	GetExpressionEx("lk!slab_caches", &slab_caches_addr, NULL);
	if (slab_caches_addr == NULL) {
		dprintf("ndx tips : failed to read lk!slab_caches address!\n");

		return;
	}
	GetFieldValue(slab_caches_addr, "lk!list_head", "next", list_head_addr);
	GetFieldOffset("lk!kmem_cache", "list", &offset);
	if (offset == NULL) {
		dprintf("ndx tips : failed to get kmem_cache.list offset!\n");

		return;
	}

	switch (slab_args.argc) {
	case 0:
		show_slab(slab_caches_addr, list_head_addr, offset);

		break;
	case 1:
		if (strncmp(slab_args.argv[0], "-s", 2) == 0) {
			show_slab_sort_by_objsize(slab_caches_addr, list_head_addr, offset);
		}
		else if (strncmp(slab_args.argv[0], "-n", 2) == 0) {
			show_slab_sort_by_objnum(slab_caches_addr, list_head_addr, offset);
		}
		else if (strncmp(slab_args.argv[0], "-t", 2) == 0) {
			show_slab_sort_by_objtotal(slab_caches_addr, list_head_addr, offset);
		}
		else {
			goto TAG_HELP;
		}

		break;
	default:
	TAG_HELP:
		print_slab_help_info();

		break;
	}

	return;
}

DECLARE_API(xdmesg)
{
	int ret;
	char fpath[MAX_PATH] = {0};
	ndx_args dmesg_args;

	dmesg_args = { 0 };

	split_args(&dmesg_args, args);

	ret = print_cmd_help_info(&dmesg_args);

	if (ret != 0) {
		goto TAG_HELP;
	}

	switch (dmesg_args.argc) {
	case 0:
		dmesg_decode_memory();

		break;
	case 1:
		snprintf(fpath, MAX_PATH, "%s", dmesg_args.argv[0]);
		dmesg_decode_file(fpath);

		break;
	default:
	TAG_HELP:
		print_dmesg_help_info();

		break;
	}

	return;
}
