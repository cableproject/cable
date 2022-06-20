/* SPDX-License-Identifier: GPL-2.0
 * Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */
static const char *__doc__ =
    "XDP monitor tool, based on tracepoints\n";

#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <ctype.h>
#include <unistd.h>
#include <locale.h>

#include <sys/resource.h>
#include <getopt.h>
#include <net/if.h>
#include <time.h>

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <libgen.h>

#include <bpf/bpf.h>
#include "bpf_util.h"
#include "bpf.h"
#include "libbpf.h"
#include "linux_resource.h"


static int ifindex;
static int verbose = 1;
static int map_fd;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;
static __u32 prog_id;

static void int_exit(int sig)
{
    __u32 curr_prog_id = 0;

    if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags))
    {
        printf("bpf_get_link_xdp_id failed\n");
        exit(1);
    }
    if (prog_id == curr_prog_id)
        bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
    else if (!curr_prog_id)
        printf("couldn't find a prog id on a given interface\n");
    else
        printf("program on interface changed, not removing\n");
    exit(0);
}
// static const struct option long_options[] = {
//     {"help", no_argument, NULL, 'h'},
//     {"debug", no_argument, NULL, 'D'},
//     {"stats", no_argument, NULL, 'S'},
//     {"sec", required_argument, NULL, 's'},
//     {0, 0, NULL, 0}};
enum
{
    CPU_USED_RATE = 0,
    PFCP = 1,
    MEM_USED_RATE = 2,
    DISK_USED_RATE = 3,
    USER =4,
};
/* C standard specifies two constants, EXIT_SUCCESS(0) and EXIT_FAILURE(1) */
#define EXIT_FAIL_MEM 5

// static void usage(char *argv[])
// {
//     int i;
//     printf("\nDOCUMENTATION:\n%s\n", __doc__);
//     printf("\n");
//     printf(" Usage: %s (options-see-below)\n",
//            argv[0]);
//     printf(" Listing options:\n");
//     for (i = 0; long_options[i].name != 0; i++)
//     {
//         printf(" --%-15s", long_options[i].name);
//         if (long_options[i].flag != NULL)
//             printf(" flag (internal value:%d)",
//                    *long_options[i].flag);
//         else
//             printf("short-option: -%c",
//                    long_options[i].val);
//         printf("\n");
//     }
//     printf("\n");
// }

#define NANOSEC_PER_SEC 1000000000 /* 10^9 */
static __u64 gettime(void)
{
    struct timespec t;
    int res;

    res = clock_gettime(CLOCK_MONOTONIC, &t);
    if (res < 0)
    {
        fprintf(stderr, "Error with gettimeofday! (%i)\n", res);
        exit(EXIT_FAILURE);
    }
    return (__u64)t.tv_sec * NANOSEC_PER_SEC + t.tv_nsec;
}

/* enum xdp_action */
#define PKG_TYPE_MAX 4

/* Common stats data record shared with _kern.c */
// struct datarec
// {
//     long gtp_u;
//     long gtp_c;
//     long gtp;
//     long unknow;
// };
#define MAX_CPUS 64

/* Userspace structs for collection of stats from maps */
struct record
{
    __u64 timestamp;
    long total;
};

struct stats_record
{
    struct record xdp_gtp_u;
    struct record xdp_gtp_c;
    struct record xdp_gtp;
    struct record xdp_unknow;
};

// static bool map_collect_record(int fd, __u32 key, struct record *rec)
// {
//     /* For percpu maps, userspace gets a value per possible CPU */
//     long value;
//     if ((bpf_map_lookup_elem(fd, &key, &value)) != 0)
//     {
//         fprintf(stderr,
//                 "ERR: bpf_map_lookup_elem failed key:0x%X\n", key);
//         return false;
//     }
//     /* Get time as close as possible to reading map contents */
//     rec->timestamp = gettime();
//     rec->total = value;
//     return true;
// }

// static double calc_period(struct record *r, struct record *p)
// {
//     double period_ = 0;
//     __u64 period = 0;

//     period = r->timestamp - p->timestamp;
//     if (period > 0)
//         period_ = ((double)period / NANOSEC_PER_SEC);

//     return period_;
// }

// static double calc_pkg(struct record *r, struct record *p, double period)
// {
//     long packets = 0;
//     double pkg = 0;

//     if (period > 0)
//     {
//         packets = r->total - p->total;
//         pkg = packets / period;
//     }
//     return pkg;
// }
// static void record_print(struct record *rec, struct record *prev)
// {
//     double t = 0, pkg = 0;
//     char *fmt2 = "%-15s '%-12.0f\n";
//     t = calc_period(rec, prev);
//     pkg = calc_pkg(rec, prev, t);
//     if (pkg > 0)
//         printf(fmt2, "xdp_gtp", pkg);
// }

// static void stats_print(struct stats_record *stats_rec,
//                         struct stats_record *stats_prev)
// {
//     /* Header */
//     printf("%-15s %-7s\n", "XDP-event", "pps");

//     /* tracepoint: xdp:xdp_exception */
//     record_print(&stats_rec->xdp_gtp, &stats_prev->xdp_gtp);
//     record_print(&stats_rec->xdp_gtp_u, &stats_prev->xdp_gtp_u);
//     record_print(&stats_rec->xdp_gtp_c, &stats_prev->xdp_gtp_c);
//     record_print(&stats_rec->xdp_unknow, &stats_prev->xdp_unknow);

//     printf("\n");
// }

static bool stats_collect(MYSQL* mysql,struct stats_record *rec, __u64 timestamp)
{
    int fd;
    /* TODO: Detect if someone unloaded the perf event_fd's, as
	 * this can happen by someone running perf-record -e
	 */

    fd = map_fd; /* map0: redirect_err_cnt */
    __u32 nextKey;
    long value;

    int result = bpf_map_get_next_key(fd, NULL, &nextKey);
    while (result > -1)
    {
        if ((bpf_map_lookup_elem(fd, &nextKey, &value)) != 0)
        {
            fprintf(stderr,
                    "ERR: bpf_map_lookup_elem failed key:0x%X\n", nextKey);
            return false;
        }
        printf("read key: %d, value %ld\n", nextKey, value);
        insertResourceMysql(mysql,timestamp,USER,value,-1,nextKey,0);

        result = bpf_map_get_next_key(fd, &nextKey, &nextKey);
    }
    // map_collect_record(fd, GTP_C, &rec->xdp_gtp_c);
    // map_collect_record(fd, GTP_U, &rec->xdp_gtp_u);
    // map_collect_record(fd, GTP, &rec->xdp_gtp);
    // map_collect_record(fd, UNKNOW, &rec->xdp_unknow);
    return true;
}

static struct stats_record *alloc_stats_record(void)
{
    struct stats_record *rec;
    /* Alloc main stats_record structure */
    rec = malloc(sizeof(*rec));
    memset(rec, 0, sizeof(*rec));
    if (!rec)
    {
        fprintf(stderr, "Mem alloc error\n");
        exit(EXIT_FAIL_MEM);
    }

    return rec;
}

static void free_stats_record(struct stats_record *r)
{

    free(r);
}

/* Pointer swap trick */
static inline void swap(struct stats_record **a, struct stats_record **b)
{
    struct stats_record *tmp;

    tmp = *a;
    *a = *b;
    *b = tmp;
}

static void stats_poll(int interval, int map_fd,MYSQL *mysql)
{
    struct stats_record *rec, *prev;

    rec = alloc_stats_record();
    prev = alloc_stats_record();
    stats_collect(mysql, rec,gettime());

    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    /* Header */
    if (verbose)
        printf("\n%s", __doc__);

    /* TODO Need more advanced stats on error types */
    //printf(" - Stats map0: %s\n", map_data[0].name);
    printf("\n");
    fflush(stdout);

    while (1)
    {
        //swap(&prev, &rec);
        stats_collect(mysql,rec,gettime());
        //stats_print(rec, prev);
        fflush(stdout);
        sleep(interval);
    }

    free_stats_record(rec);
    free_stats_record(prev);
}

// static void print_bpf_prog_info(void)
// {
//     int i;

//     /* Prog info */
//     printf("Loaded BPF prog have %d bpf program(s)\n", prog_cnt);
//     for (i = 0; i < prog_cnt; i++)
//     {
//         printf(" - prog_fd[%d] = fd(%d)\n", i, prog_fd[i]);
//     }

//     /* Maps info */
//     printf("Loaded BPF prog have %d map(s)\n", map_data_count);
//     for (i = 0; i < map_data_count; i++)
//     {
//         char *name = map_data[i].name;
//         int fd = map_data[i].fd;

//         printf(" - map_data[%d] = fd(%d) name:%s\n", i, fd, name);
//     }

//     /* Event info */
//     printf("Searching for (max:%d) event file descriptor(s)\n", prog_cnt);
//     for (i = 0; i < prog_cnt; i++)
//     {
//         if (event_fd[i] != -1)
//             printf(" - event_fd[%d] = fd(%d)\n", i, event_fd[i]);
//     }
// }

int main(int argc, char **argv)
{
    struct rlimit r = {RLIM_INFINITY, RLIM_INFINITY};
    int ret = EXIT_SUCCESS;

    /* Default settings: */
    int interval = 2;

    struct bpf_prog_load_attr prog_load_attr = {
        .prog_type = BPF_PROG_TYPE_XDP,
    };
    struct bpf_prog_info info = {};
    __u32 info_len = sizeof(info);
    int prog_fd;
    struct bpf_object *obj;
    struct bpf_map *map;
    char filename[256];
    int err;

    if (setrlimit(RLIMIT_MEMLOCK, &r))
    {
        perror("setrlimit(RLIMIT_MEMLOCK)");
        return 1;
    }

    ifindex = if_nametoindex(argv[optind]);
    if (!ifindex)
    {
        perror("if_nametoindex");
        return 1;
    }

    snprintf(filename, sizeof(filename), "my_xdp_monitor_down_kern.o");
    prog_load_attr.file = filename;

    // 加载bpf模块
    if (bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd))
        return 1;

    map = bpf_map__next(NULL, obj);
    if (!map)
    {
        printf("finding a map in obj file failed\n");
        return 1;
    }
    map_fd = bpf_map__fd(map);

    if (!prog_fd)
    {
        printf("load_bpf_file: %s\n", strerror(errno));
        return 1;
    }

    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    // 绑定网卡
    if (bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags) < 0)
    {
        printf("link set xdp fd failed\n");
        return 1;
    }

    err = bpf_obj_get_info_by_fd(prog_fd, &info, &info_len);
    if (err)
    {
        printf("can't get prog info - %s\n", strerror(errno));
        return err;
    }
    prog_id = info.id;
    // 初始化mysql
    MYSQL *mysql = initResourceMysql();

    stats_poll(interval, map_fd, mysql);
    closeMysql(mysql);

    return ret;
}
