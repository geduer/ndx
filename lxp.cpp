#include "common.h"
#include "lxp.h"

typedef struct ndx_task_struct_simple_info {
	char comm[MAX_PATH];
	int pid;
	LONG64 state;
	ULONG64 stack;
	ULONG64 flags;
	ULONG64 addr;
	ULONG64 next_addr;
} ndx_task_simple;

typedef struct ndx_task_struct_base_info {
	char comm[MAX_PATH];
	int pid;
	/*
	 *	a thread group all threads have the same pid[pid_h] as the lead thread,
	 *	and this pid_h is stored in the tgid field,
	 *	which returns the tgid value of the current process, not the value of pid.
	 */
	int tgid;
	int ppid;					// parent process id
	LONG64 state;
	ULONG64 stack;
	int exit_state;
	int exit_code;
	int exit_signal;			// related to stat and exit_state
	int prio;					// dynamic priority
	int	static_prio;			// static priority
	unsigned int rt_priority;	// real-time priority
	ULONG64 utime;
	ULONG64 stime;
	ULONG64 gtime;
	ULONG64 flags;				// task flags
	ULONG64 start_time;			// monotonic time in nsec
	ULONG64 real_start_time;	// boot based time in nsec
	ULONG64 addr;
	ULONG64 next_addr;			// task_struct linked list
} ndx_task_base;

static ULONG64 get_next_addr(ULONG64 current_addr)
{
	ULONG64 next_addr;
	ULONG tasks_offset;

	next_addr = 0;

	GetFieldOffset("lk!task_struct", "tasks", &tasks_offset);
	GetFieldValue(current_addr, "lk!task_struct", "tasks.next", next_addr);
	next_addr = next_addr - tasks_offset;

	return next_addr;
}

static int get_task_base_info(ULONG64 current_addr, ndx_task_base* task_base, struct ndx_lxp_option* lxp_option)
{
	int ret;

	ret = 0;

	GetFieldData(current_addr, "lk!task_struct", "comm", MAX_PATH, task_base->comm);

	switch (lxp_option->filter) {
	case 202:
		if (strstr(task_base->comm, lxp_option->comm) == NULL) {
			// dprintf("ignore processes with comm : %s\n", task_base->comm);

			ret = -1;
			goto TAG_GET_NEXT_ADDR;
		}
	default:
		break;
	}

	GetFieldValue(current_addr, "lk!task_struct", "pid", task_base->pid);
	GetFieldValue(current_addr, "lk!task_struct", "tgid", task_base->tgid);
	GetFieldValue(current_addr, "lk!task_struct", "ppid", task_base->ppid);
	GetFieldValue(current_addr, "lk!task_struct", "state", task_base->state);
	GetFieldValue(current_addr, "lk!task_struct", "stack", task_base->stack);
	GetFieldValue(current_addr, "lk!task_struct", "exit_state", task_base->exit_state);
	GetFieldValue(current_addr, "lk!task_struct", "exit_code", task_base->exit_code);
	GetFieldValue(current_addr, "lk!task_struct", "exit_signal", task_base->exit_signal);
	GetFieldValue(current_addr, "lk!task_struct", "prio", task_base->prio);
	GetFieldValue(current_addr, "lk!task_struct", "static_prio", task_base->static_prio);
	GetFieldValue(current_addr, "lk!task_struct", "rt_priority", task_base->rt_priority);
	GetFieldValue(current_addr, "lk!task_struct", "utime", task_base->utime);
	GetFieldValue(current_addr, "lk!task_struct", "stime", task_base->stime);
	GetFieldValue(current_addr, "lk!task_struct", "gtime", task_base->gtime);
	GetFieldValue(current_addr, "lk!task_struct", "flags", task_base->flags);
	GetFieldValue(current_addr, "lk!task_struct", "start_time", task_base->start_time);
	GetFieldValue(current_addr, "lk!task_struct", "real_start_time", task_base->real_start_time);

TAG_GET_NEXT_ADDR:
	task_base->addr = current_addr;
	task_base->next_addr = get_next_addr(current_addr);

	return ret;
}

static int get_task_simple_info(ULONG64 current_addr, ndx_task_simple* task_simple, struct ndx_lxp_option* lxp_option)
{
	int ret;

	ret = 0;

	GetFieldData(current_addr, "lk!task_struct", "comm", MAX_PATH, task_simple->comm);

	switch (lxp_option->filter) {
	case 202:
		if (strstr(task_simple->comm, lxp_option->comm) == NULL) {
			// dprintf("ignore processes with comm : %s\n", task_simple->comm);

			ret = -1;
			goto TAG_GET_NEXT_ADDR;
		}

		break;
	default:
		break;
	}

	GetFieldValue(current_addr, "lk!task_struct", "pid", task_simple->pid);
	GetFieldValue(current_addr, "lk!task_struct", "state", task_simple->state);
	GetFieldValue(current_addr, "lk!task_struct", "stack", task_simple->stack);
	GetFieldValue(current_addr, "lk!task_struct", "flags", task_simple->flags);

TAG_GET_NEXT_ADDR:
	task_simple->addr = current_addr;
	task_simple->next_addr = get_next_addr(current_addr);

	return ret;
}

static void print_task_base_info(ndx_task_base* task_base, int pnum)
{
	dprintf("\n");

	dprintf("get process number : %d\n", pnum);
	dprintf("| %-12s | %-42s |\n", "pid", "comm");
	dprintf("| %-12d | %-42s |\n", task_base->pid, task_base->comm);

	dprintf("| %-27s | %-27s |\n", "task address", "next task address");
	dprintf("| 0x%-25llx | 0x%-25llx |\n", task_base->addr, task_base->next_addr);

	dprintf("| %-12s | %-12s | %-12s | %-12s |\n", "utime", "stime", "gtime", "start_time");
	dprintf("| %-12d | %-12d | %-12d | %-12d |\n", task_base->utime, task_base->stime, task_base->gtime, task_base->start_time);

	dprintf("| %-12s | %-12s | %-12s | %-12s |\n", "state", "exit_state", "exit_code", "exit_signal");
	dprintf("| %-12d | %-12d | %-12d | %-12d |\n", task_base->state, task_base->exit_state, task_base->exit_code, task_base->exit_signal);

	dprintf("| %-12s | %-12s | %-12s | %-12s |\n", "flags", "prio", "static_prio", "rt_priority");
	dprintf("| 0x%-10llx | %-12d | %-12d | %-12d |\n", task_base->flags, task_base->prio, task_base->static_prio, task_base->rt_priority);

	return;
}

static void print_task_simple_info(ndx_task_simple* task_simple, int pnum)
{
	dprintf("\n");

	dprintf("get process number : %d\n", pnum);
	dprintf("| %-12s | %-42s |\n", "pid", "comm");
	dprintf("| %-12d | %-42s |\n", task_simple->pid, task_simple->comm);

	dprintf("| %-27s | %-27s |\n", "task address", "next task address");
	dprintf("| 0x%-25llx | 0x%-25llx |\n", task_simple->addr, task_simple->next_addr);

	dprintf("| %-12s | %-12s | %-27s |\n", "state", "flags", "stack");
	dprintf("| %-12d | %-12d | 0x%-25llx |\n", task_simple->state, task_simple->flags, task_simple->stack);

	return;
}

static void show_tasks_list_base_info(int type, ULONG64 task_addr, struct ndx_lxp_option* lxp_option)
{
	ULONG64 current_addr;
	ndx_task_base task_base;
	int pnum, ret;

	task_base = { 0 };
	current_addr = task_addr;
	pnum = 0;
	ret = 0;

	do
	{
		pnum++;

		if (CheckControlC() == TRUE) {
			break;
		}

		ret = get_task_base_info(current_addr, &task_base, lxp_option);
		if (ret == 0) {
			print_task_base_info(&task_base, pnum);
		}

		current_addr = task_base.next_addr;

	} while (current_addr != task_addr && current_addr != NULL && (lxp_option->pcnt < 0 || pnum < lxp_option->pcnt));

	return;
}

static void show_tasks_list_simple_info(int type, ULONG64 task_addr, struct ndx_lxp_option* lxp_option)
{
	ULONG64 current_addr;
	ndx_task_simple task_simple;
	int pnum, ret;

	task_simple = { 0 };
	current_addr = task_addr;
	pnum = 0;
	ret = 0;

	do
	{
		pnum++;

		if (CheckControlC() == TRUE) {
			break;
		}

		ret = get_task_simple_info(current_addr, &task_simple, lxp_option);
		if (ret == 0) {
			print_task_simple_info(&task_simple, pnum);
		}

		current_addr = task_simple.next_addr;

	} while (current_addr != task_addr && current_addr != NULL && (lxp_option->pcnt < 0 || pnum < lxp_option->pcnt));

	return;
}

void show_task_base_info(ULONG64 task_addr, struct ndx_lxp_option* lxp_option)
{
	ULONG64 current_addr;
	ndx_task_base task_base;

	task_base = { 0 };
	current_addr = task_addr;

	switch (lxp_option->filter) {
	case 200:
		get_task_base_info(current_addr, &task_base, lxp_option);
		print_task_base_info(&task_base, 1);

		break;
	default:
		show_tasks_list_base_info(0, current_addr, lxp_option);

		break;
	}

	return;
}


void show_task_simple_info(ULONG64 task_addr, struct ndx_lxp_option* lxp_option)
{
	ULONG64 current_addr;
	ndx_task_simple task_simple;

	task_simple = { 0 };
	current_addr = task_addr;

	switch (lxp_option->filter) {
	case 200:
		get_task_simple_info(current_addr, &task_simple, lxp_option);
		print_task_simple_info(&task_simple, 1);

		break;
	default:
		show_tasks_list_simple_info(0, current_addr, lxp_option);

		break;
	}

	return;
}

void get_lxp_option(struct ndx_args* args_info, struct ndx_lxp_option* lxp_option)
{
	int base;

	base = 0;

	if (args_info->argc < 1) {
		lxp_option->flag = 100;

		return;
	}

	if (args_info->has_addr == true) {
		base = 1;

		switch (args_info->argc) {
		case 2:
			goto TAG_GET_FLAG;
		case 3:
			goto TAG_GET_FILTER;
		}
	}
	else {
		base = 0;

		switch (args_info->argc) {
		case 1:
			goto TAG_GET_FLAG;
		case 2:
			goto TAG_GET_FILTER;
		}
	}

TAG_GET_FILTER:
	if (strncmp(args_info->argv[base + 1], "0", 2) == 0) {
		lxp_option->filter = 201;
		lxp_option->pcnt = -1;
	}
	else if (strncmp(args_info->argv[base + 1], "-n", 2) == 0) {
		snprintf(lxp_option->comm, MAX_ARG_LEN, "%s", args_info->argv[base + 1] + 2);

		lxp_option->filter = 202;
		lxp_option->pcnt = -1;
	}
	else if (strncmp(args_info->argv[base + 1], "-c", 2) == 0) {
		sscanf_s(args_info->argv[base + 1] + 2, "%d", &lxp_option->pcnt);

		lxp_option->filter = 203;
	}
	else {
		lxp_option->filter = 200;
	}

TAG_GET_FLAG:
	if (strncmp(args_info->argv[base], "0", 2) == 0) {
		lxp_option->flag = 101;
	}
	else if (strncmp(args_info->argv[base], "1", 2) == 0) {
		lxp_option->flag = 102;
	}
	else {
		lxp_option->flag = 100;
	}

	return;
}
