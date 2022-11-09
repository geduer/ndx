#ifndef __NDX_SLAB_H__

#define __NDX_SLAB_H__

void show_slab(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset);
void show_slab_sort_by_objsize(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset);
void show_slab_sort_by_objnum(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset);
void show_slab_sort_by_objtotal(ULONG64 slab_caches_addr, ULONG64 list_head_addr, ULONG list_offset);

#endif
