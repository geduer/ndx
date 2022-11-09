#include "common.h"
#include <vector>
#include <algorithm>

using namespace std;

typedef struct ndx_linux_list_head {
	struct list_head* next, * prev;
} linux_list_head;

struct ndx_slab_info {
	char name[MAX_PATH];
	int refs;
	int align;
	unsigned int object_size;
	unsigned int slab_size;
	unsigned int useroffset;
	unsigned int usersize;
	linux_list_head list;
	unsigned int objects_total;
	unsigned int total;
	unsigned int objperslab;
};

static bool compare_slabv_size(ndx_slab_info a, ndx_slab_info b)
{
	return (a.object_size > b.object_size);
}

static bool compare_slabv_num(ndx_slab_info a, ndx_slab_info b)
{
	return (a.objects_total > b.objects_total);
}

static bool compare_slabv_total(ndx_slab_info a, ndx_slab_info b)
{
	return (a.total > b.total);
}

static void print_slab_info(ndx_slab_info* slab_info, int snum)
{
	dprintf("<-- %-6d --> <-- %s -->\n| %-8d | %-8d | %-8d | %-8d | %-8d | %-8d | %-9d | %-8d | %-8d |\n",
		snum, slab_info->name, slab_info->total, slab_info->objects_total, slab_info->objperslab,
		slab_info->object_size, slab_info->slab_size, slab_info->align, slab_info->useroffset,
		slab_info->usersize, slab_info->refs);

	return;
}

static void read_slab_info(ULONG64 addr, ndx_slab_info* slab_info)
{
	ULONG64 field_ptr;
	unsigned int temp;
	ULONG offset;
	char name[MAX_PATH] = { 0 };

	GetFieldOffset("lk!kmem_cache", "name", &offset);
	ReadPointer(addr + offset, &field_ptr);
	ReadMemory(field_ptr, &name, sizeof(name), NULL);
	snprintf(slab_info->name, MAX_PATH, "%s", name);

	slab_info->refs = read_uint32(addr, "lk!kmem_cache", "refcount");
	slab_info->align = read_uint32(addr, "lk!kmem_cache", "align");
	slab_info->object_size = read_uint32(addr, "lk!kmem_cache", "object_size");
	slab_info->slab_size = read_uint32(addr, "lk!kmem_cache", "size");
	slab_info->useroffset = read_uint32(addr, "lk!kmem_cache", "useroffset");
	slab_info->usersize = read_uint32(addr, "lk!kmem_cache", "usersize");

	temp = read_uint32(addr, "lk!kmem_cache", "oo");
	slab_info->objperslab = temp & (0x0000ffff);
	slab_info->objects_total = slab_info->objperslab;
	slab_info->total = slab_info->slab_size * slab_info->objects_total;

	GetFieldOffset("lk!kmem_cache", "list", &offset);
	ReadMemory(addr + offset, &slab_info->list, sizeof(linux_list_head), NULL);

	return;
}

static vector <ndx_slab_info> get_slab_list(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset)
{
	ULONG64 current_addr;
	ndx_slab_info slab_info;
	vector <ndx_slab_info> slabv;

	current_addr = list_head_addr;
	slab_info = { 0 };

	dprintf("<-- %s --> <-- %s -->\n| %-8s | %-8s | %-8s | %-8s | %-8s | %-8s | %-9s | %-8s | %-8s |\n",
		"num", "name", "objtotal", "objnum", "perslab", "objsize", "slabsize",
		"algin", "usroffset", "usrsize", "refcount");

	do {
		if (CheckControlC() == TRUE) {
			return slabv;
		}

		read_slab_info(current_addr - list_offset, &slab_info);

		slabv.push_back(slab_info);

		current_addr = (ULONG64)slab_info.list.next;
	} while (current_addr != list_head_addr && current_addr != NULL);

	return slabv;
}

void show_slab(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset)
{
	vector <ndx_slab_info> slabv;

	slabv = get_slab_list(slab_caches_addr, list_head_addr, list_offset);

	for (int i = 0; i < slabv.size() - 1; i++) {
		if (CheckControlC() == TRUE) {
			return;
		}

		print_slab_info(&slabv[i], i);
	}

	return;
}

/*
 *	The last element of slabv is garbled,
 *	and will be ranked first when sorting,
 *	in order to skip this garbled code, so set i=1
 */

void show_slab_sort_by_objsize(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset)
{
	int i;
	vector <ndx_slab_info> slabv;

	slabv = get_slab_list(slab_caches_addr, list_head_addr, list_offset);

	std::sort(slabv.begin(), slabv.end(), compare_slabv_size);

	for (i = 1; i < slabv.size(); i++) {
		if (CheckControlC() == TRUE) {
			return;
		}

		print_slab_info(&slabv[i], i);
	}

	return;
}

void show_slab_sort_by_objnum(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset)
{
	int i;
	vector <ndx_slab_info> slabv;

	slabv = get_slab_list(slab_caches_addr, list_head_addr, list_offset);

	std::sort(slabv.begin(), slabv.end(), compare_slabv_num);

	for (i = 1; i < slabv.size() - 1; i++) {
		if (CheckControlC() == TRUE) {
			return;
		}

		print_slab_info(&slabv[i], i);
	}

	return;
}

void show_slab_sort_by_objtotal(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset)
{
	int i;
	vector <ndx_slab_info> slabv;

	slabv = get_slab_list(slab_caches_addr, list_head_addr, list_offset);

	std::sort(slabv.begin(), slabv.end(), compare_slabv_total);

	for (i = 1; i < slabv.size(); i++) {
		if (CheckControlC() == TRUE) {
			return;
		}

		print_slab_info(&slabv[i], i);
	}

	return;
}
