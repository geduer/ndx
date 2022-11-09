#ifndef __NDX_LXP_H__

#define __NDX_LXP_H__

typedef struct ndx_lxp_option {
	int flag;
	int filter;
	int pcnt;
	char comm[MAX_PATH];
} ndx_lxp_option;

void show_task_base_info(ULONG64 task_addr, struct ndx_lxp_option* lxp_option);
void show_task_simple_info(ULONG64 task_addr, struct ndx_lxp_option* lxp_option);
void get_lxp_option(struct ndx_args* args_info, struct ndx_lxp_option* lxp_option);

#endif
