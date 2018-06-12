#ifndef __BPF_HELPERS_H
#define __BPF_HELPERS_H

/* Additional headers */
# define printk(fmt, ...)                                               \
                ({                                                      \
                        char ____fmt[] = fmt;                           \
                        bpf_trace_printk(____fmt, sizeof(____fmt),      \
                                     ##__VA_ARGS__);                    \
                })


#include <stdbool.h>
#include <stdio.h>
typedef signed char s8;
typedef unsigned char u8;
typedef signed short s16;
typedef unsigned short u16;
typedef signed int s32;
typedef unsigned int u32;
typedef signed long long s64;
typedef unsigned long long u64;

#ifndef ___constant_swab16
#define ___constant_swab16(x) ((__u16)(             \
    (((__u16)(x) & (__u16)0x00ffU) << 8) |          \
    (((__u16)(x) & (__u16)0xff00U) >> 8)))
#endif

#ifndef ___constant_swab32
#define ___constant_swab32(x) ((__u32)(             \
    (((__u32)(x) & (__u32)0x000000ffUL) << 24) |        \
    (((__u32)(x) & (__u32)0x0000ff00UL) <<  8) |        \
    (((__u32)(x) & (__u32)0x00ff0000UL) >>  8) |        \
    (((__u32)(x) & (__u32)0xff000000UL) >> 24)))
#endif

#ifndef ___constant_swab64
#define ___constant_swab64(x) ((__u64)(             \
    (((__u64)(x) & (__u64)0x00000000000000ffULL) << 56) |   \
    (((__u64)(x) & (__u64)0x000000000000ff00ULL) << 40) |   \
    (((__u64)(x) & (__u64)0x0000000000ff0000ULL) << 24) |   \
    (((__u64)(x) & (__u64)0x00000000ff000000ULL) <<  8) |   \
    (((__u64)(x) & (__u64)0x000000ff00000000ULL) >>  8) |   \
    (((__u64)(x) & (__u64)0x0000ff0000000000ULL) >> 24) |   \
    (((__u64)(x) & (__u64)0x00ff000000000000ULL) >> 40) |   \
    (((__u64)(x) & (__u64)0xff00000000000000ULL) >> 56)))
#endif

#if __BYTE_ORDER__ == __ORDER_LITTLE_ENDIAN__
#ifndef __constant_htonll
#define __constant_htonll(x) (___constant_swab64((x)))
#endif

#ifndef __constant_ntohll
#define __constant_ntohll(x) (___constant_swab64((x)))
#endif

#define __constant_htonl(x) (___constant_swab32((x)))
#define __constant_ntohl(x) (___constant_swab32(x))
#define __constant_htons(x) (___constant_swab16((x)))
#define __constant_ntohs(x) ___constant_swab16((x))

#elif __BYTE_ORDER__ == __ORDER_BIG_ENDIAN__
# warning "I never tested BIG_ENDIAN machine!"
#define __constant_htonll(x) (x)
#define __constant_ntohll(X) (x)
#define __constant_htonl(x) (x)
#define __constant_ntohl(x) (x)
#define __constant_htons(x) (x)
#define __constant_ntohs(x) (x)
#define htonl(d) __constant_htonl(d)
#define htons(d) __constant_htons(d)
#else
# error "Fix your compiler's __BYTE_ORDER__?!"
#endif
/* END */

/* helper macro to place programs, maps, license in
 * different sections in elf_bpf file. Section names
 * are interpreted by elf_bpf loader
 */
#define SEC(NAME) __attribute__((section(NAME), used))

/* helper functions called from eBPF programs written in C */
static void *(*bpf_map_lookup_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_lookup_elem;
static int (*bpf_map_update_elem)(void *map, void *key, void *value,
				  unsigned long long flags) =
	(void *) BPF_FUNC_map_update_elem;
static int (*bpf_map_delete_elem)(void *map, void *key) =
	(void *) BPF_FUNC_map_delete_elem;
static int (*bpf_probe_read)(void *dst, int size, void *unsafe_ptr) =
	(void *) BPF_FUNC_probe_read;
static unsigned long long (*bpf_ktime_get_ns)(void) =
	(void *) BPF_FUNC_ktime_get_ns;
static int (*bpf_trace_printk)(const char *fmt, int fmt_size, ...) =
	(void *) BPF_FUNC_trace_printk;
static void (*bpf_tail_call)(void *ctx, void *map, int index) =
	(void *) BPF_FUNC_tail_call;
static unsigned long long (*bpf_get_smp_processor_id)(void) =
	(void *) BPF_FUNC_get_smp_processor_id;
static unsigned long long (*bpf_get_current_pid_tgid)(void) =
	(void *) BPF_FUNC_get_current_pid_tgid;
static unsigned long long (*bpf_get_current_uid_gid)(void) =
	(void *) BPF_FUNC_get_current_uid_gid;
static int (*bpf_get_current_comm)(void *buf, int buf_size) =
	(void *) BPF_FUNC_get_current_comm;
static int (*bpf_perf_event_read)(void *map, int index) =
	(void *) BPF_FUNC_perf_event_read;
static int (*bpf_clone_redirect)(void *ctx, int ifindex, int flags) =
	(void *) BPF_FUNC_clone_redirect;
static int (*bpf_redirect)(int ifindex, int flags) =
	(void *) BPF_FUNC_redirect;
static int (*bpf_perf_event_output)(void *ctx, void *map,
				    unsigned long long flags, void *data,
				    int size) =
	(void *) BPF_FUNC_perf_event_output;
static int (*bpf_get_stackid)(void *ctx, void *map, int flags) =
	(void *) BPF_FUNC_get_stackid;
static int (*bpf_probe_write_user)(void *dst, void *src, int size) =
	(void *) BPF_FUNC_probe_write_user;
static int (*bpf_current_task_under_cgroup)(void *map, int index) =
	(void *) BPF_FUNC_current_task_under_cgroup;
static int (*bpf_skb_get_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_get_tunnel_key;
static int (*bpf_skb_set_tunnel_key)(void *ctx, void *key, int size, int flags) =
	(void *) BPF_FUNC_skb_set_tunnel_key;
static int (*bpf_skb_get_tunnel_opt)(void *ctx, void *md, int size) =
	(void *) BPF_FUNC_skb_get_tunnel_opt;
static int (*bpf_skb_set_tunnel_opt)(void *ctx, void *md, int size) =
	(void *) BPF_FUNC_skb_set_tunnel_opt;
static unsigned long long (*bpf_get_prandom_u32)(void) =
	(void *) BPF_FUNC_get_prandom_u32;
static int (*bpf_xdp_adjust_head)(void *ctx, int offset) =
	(void *) BPF_FUNC_xdp_adjust_head;


#define load_byte(data, b)  (*(((u8*)(data)) + (b)))
#define load_half(data, b) __constant_ntohs(*(u16 *)((u8*)(data) + (b)))
#define load_word(data, b) __constant_ntohl(*(u32 *)((u8*)(data) + (b)))
#define load_dword(data, b) __constant_ntohl(*(u64 *)((u8*)(data) + (b)))
#define htonl(d) __constant_htonl(d)
#define htons(d) __constant_htons(d)

/* a helper structure used by eBPF C program
 * to describe map attributes to elf_bpf loader
 */
struct bpf_map_def {
	unsigned int type;
	unsigned int key_size;
	unsigned int value_size;
	unsigned int max_entries;
    unsigned int map_flags;
    unsigned int id;
    unsigned int pinning;
};

/* used in TC */
struct bpf_elf_map {
        __u32 type;
        __u32 key_size;
        __u32 value_size;
        __u32 max_entries;
        __u32 map_flags;
        __u32 id;
        __u32 pinning;
};

#define REGISTER_START()
#define REGISTER_TABLE(NAME, TYPE, KEY_SIZE, VALUE_SIZE, MAX_ENTRIES) \
struct bpf_map_def SEC("maps") NAME = {          \
    .type       = TYPE,             \
    .key_size   = KEY_SIZE,         \
    .value_size = VALUE_SIZE,       \
    .max_entries    = MAX_ENTRIES,  \
    .map_flags = 0,                 \
    .pinning = 2,                   \
};
#define REGISTER_END()

#define BPF_MAP_LOOKUP_ELEM(table, key) bpf_map_lookup_elem(&table, key)
#define BPF_MAP_UPDATE_ELEM(table, key, value, flags) bpf_map_update_elem(&table, key, value, flags)

static int (*bpf_skb_load_bytes)(void *ctx, int off, void *to, int len) =
	(void *) BPF_FUNC_skb_load_bytes;
static int (*bpf_skb_store_bytes)(void *ctx, int off, void *from, int len, int flags) =
	(void *) BPF_FUNC_skb_store_bytes;
static int (*bpf_l3_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l3_csum_replace;
static int (*bpf_l4_csum_replace)(void *ctx, int off, int from, int to, int flags) =
	(void *) BPF_FUNC_l4_csum_replace;
static int (*bpf_skb_under_cgroup)(void *ctx, void *map, int index) =
	(void *) BPF_FUNC_skb_under_cgroup;
static int (*bpf_skb_change_head)(void *, int len, int flags) =
	(void *) BPF_FUNC_skb_change_head;

#if defined(__x86_64__)

#define PT_REGS_PARM1(x) ((x)->di)
#define PT_REGS_PARM2(x) ((x)->si)
#define PT_REGS_PARM3(x) ((x)->dx)
#define PT_REGS_PARM4(x) ((x)->cx)
#define PT_REGS_PARM5(x) ((x)->r8)
#define PT_REGS_RET(x) ((x)->sp)
#define PT_REGS_FP(x) ((x)->bp)
#define PT_REGS_RC(x) ((x)->ax)
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->ip)

#elif defined(__s390x__)

#define PT_REGS_PARM1(x) ((x)->gprs[2])
#define PT_REGS_PARM2(x) ((x)->gprs[3])
#define PT_REGS_PARM3(x) ((x)->gprs[4])
#define PT_REGS_PARM4(x) ((x)->gprs[5])
#define PT_REGS_PARM5(x) ((x)->gprs[6])
#define PT_REGS_RET(x) ((x)->gprs[14])
#define PT_REGS_FP(x) ((x)->gprs[11]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->gprs[2])
#define PT_REGS_SP(x) ((x)->gprs[15])
#define PT_REGS_IP(x) ((x)->psw.addr)

#elif defined(__aarch64__)

#define PT_REGS_PARM1(x) ((x)->regs[0])
#define PT_REGS_PARM2(x) ((x)->regs[1])
#define PT_REGS_PARM3(x) ((x)->regs[2])
#define PT_REGS_PARM4(x) ((x)->regs[3])
#define PT_REGS_PARM5(x) ((x)->regs[4])
#define PT_REGS_RET(x) ((x)->regs[30])
#define PT_REGS_FP(x) ((x)->regs[29]) /* Works only with CONFIG_FRAME_POINTER */
#define PT_REGS_RC(x) ((x)->regs[0])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->pc)

#elif defined(__powerpc__)

#define PT_REGS_PARM1(x) ((x)->gpr[3])
#define PT_REGS_PARM2(x) ((x)->gpr[4])
#define PT_REGS_PARM3(x) ((x)->gpr[5])
#define PT_REGS_PARM4(x) ((x)->gpr[6])
#define PT_REGS_PARM5(x) ((x)->gpr[7])
#define PT_REGS_RC(x) ((x)->gpr[3])
#define PT_REGS_SP(x) ((x)->sp)
#define PT_REGS_IP(x) ((x)->nip)

#endif

#ifdef __powerpc__
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({ (ip) = (ctx)->link; })
#define BPF_KRETPROBE_READ_RET_IP		BPF_KPROBE_READ_RET_IP
#else
#define BPF_KPROBE_READ_RET_IP(ip, ctx)		({				\
		bpf_probe_read(&(ip), sizeof(ip), (void *)PT_REGS_RET(ctx)); })
#define BPF_KRETPROBE_READ_RET_IP(ip, ctx)	({				\
		bpf_probe_read(&(ip), sizeof(ip),				\
				(void *)(PT_REGS_FP(ctx) + sizeof(ip))); })
#endif

#endif
