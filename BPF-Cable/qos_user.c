// SPDX-License-Identifier: GPL-2.0-only
/* Copyright (c) 2016 Facebook
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

#include "bpf_load.h"
#include <time.h>
#include <netinet/in.h>

#define MAX_INDEX 64
#define ETH_ALEN	6

static int ifindex;
static __u32 xdp_prog_fd;
static __u32 xdp_flags = XDP_FLAGS_UPDATE_IF_NOEXIST;

static int array_fd = -1;
static int ifindex;
static int verbose = 1;
struct xdpkey
{
    __u32 type;
    __u64 ip;
    __u64 teid;
};

struct edt {
	__u64 bps;
	__u64 t_last;
	__u64 t_horizon_drop;
};


/* match ue by info */
struct pdrs{
    __u8 src_mac[ETH_ALEN];
    __u8 des_mac[ETH_ALEN];
    __u32 src_ip;
    __u32 des_ip;
    __u8 qfi;
};

/* connect with gtp protocol between upfs*/
struct psa_gtpu{
    __u8 src_mac[ETH_ALEN];
    __u8 des_mac[ETH_ALEN];
    __u32 src_ip;
    __u32 des_ip;
    __u32 teid;
};
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
#define MAX_CPUS 64

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

static void usage(void)
{
	printf("Usage: tc_redirect_qos [...]\n");
	printf("       -U <file>   Update an already pinned BPF array\n");
	printf("       -i <ifindex> Interface index\n");
	printf("       -h          Display this help\n");
}


static int do_attach(int ifindex, int prog_fd)
{
	int err;

	err = bpf_set_link_xdp_fd(ifindex, prog_fd, xdp_flags);
	if (err < 0) {
		printf("ERROR: failed to attach program to %d\n", ifindex);
	}
	return err;
}


static void int_exit(int sig)
{
	__u32 curr_prog_id = 0;

	if (bpf_get_link_xdp_id(ifindex, &curr_prog_id, xdp_flags)) {
		printf("bpf_get_link_xdp_id failed\n");
		exit(1);
	}
	if (xdp_prog_fd == curr_prog_id)
		bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);
	else if (!curr_prog_id)
		printf("couldn't find a prog id on a given interface\n");
	else
		printf("curr_program %d on interface, origin prog fd %d, not removing\n", 
		curr_prog_id, xdp_prog_fd);
        bpf_set_link_xdp_fd(ifindex, -1, xdp_flags);

	close(array_fd);
	exit(0);
}


static int mac_str_to_bin( char *str, unsigned  char *mac)
{
    int i;
    char *s, *e=NULL;
    if ((mac == NULL) || (str == NULL)) {
        return -1;
    }
    s = (char *) str;
    for (i = 0; i < 6; ++i) {
        mac[i] = s ? strtoul (s, &e, 16) : 0;
        if (s)
            s = (*e) ? e + 1 : e;
    }
    return 0;
}
static bool stats_collect(MYSQL* mysql,struct stats_record *rec, __u64 timestamp,int gtp_monitor_map_fd)
{
    int fd;
    /* TODO: Detect if someone unloaded the perf event_fd's, as
	 * this can happen by someone running perf-record -e
	 */

    fd = gtp_monitor_map_fd; /* map0: redirect_err_cnt */
    struct xdpkey nextKey;

    long value;
    int result = bpf_map_get_next_key(fd, NULL, &nextKey);
    printf("\nresult %d", result);

    while (result > -1)
    {
        if ((bpf_map_lookup_elem(fd, &nextKey, &value)) != 0)
        {
            fprintf(stderr,
                    "ERR: bpf_map_lookup_elem failed key:%d\n", nextKey.type);
            return false;
        }
        printf("read type: %d, ip: %lld,teid: %lld,value %ld\n", nextKey.type,nextKey.ip,nextKey.teid, value);
        if(nextKey.type ==PFCP){
        insertResourceMysql(mysql,timestamp,PFCP,value,-1,nextKey.ip,1);

        }else{
        insertResourceMysql(mysql,timestamp,USER,value,nextKey.teid,nextKey.ip,1);
        }

        result = bpf_map_get_next_key(fd, &nextKey, &nextKey);
    }
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

static void stats_poll(int interval, int gtp_monitor_map_fd,MYSQL *mysql)
{
    struct stats_record *rec, *prev;

    rec = alloc_stats_record();
    prev = alloc_stats_record();
    stats_collect(mysql, rec,gettime(),gtp_monitor_map_fd);

    /* Trick to pretty printf with thousands separators use %' */
    setlocale(LC_NUMERIC, "en_US");

    /* Header */
    if (verbose)
        printf("\n%s", __doc__);

    printf("\n");
    fflush(stdout);

    while (1)
    {
        __u64 timestamp = gettime();
        stats_collect(mysql, rec,timestamp,gtp_monitor_map_fd);
        double cpuRate = getCpuRate();
        MEM_PACK* mem = get_memoccupy();
        DEV_MEM *disk = get_devmem();
        printf("cpu rate:%f, mem used rate: %f, disk used rate:%f \n",cpuRate,mem->used_rate,disk->used_rate);
        insertResourceMysql(mysql,timestamp,CPU_USED_RATE,cpuRate,-1,-1,-1);
        insertResourceMysql(mysql,timestamp,MEM_USED_RATE,mem->used_rate,-1,-1,-1);
        insertResourceMysql(mysql,timestamp,DISK_USED_RATE,disk->used_rate,-1,-1,-1);

        fflush(stdout);
        sleep(interval);
    }

    free_stats_record(rec);
    free_stats_record(prev);
}

int main(int argc, char **argv)
{
	const char *pinned_file = "/sys/fs/bpf/tc/globals/m_qers";

	int err = -1;
	int map_pdr_fd = -1;
	int map_gtpu_fd = -1;
	int gtp_monitor_map_fd = -1;

    /* Default settings: */
    int interval = 5;

	int num_kBps = 70;
	int opt;
	
	struct bpf_object *obj;	
	struct edt val;
	struct pdrs pdr1, pdr2;
	struct psa_gtpu psa_info;

    __u32 key;
	
	while ((opt = getopt(argc, argv, "F:U:i:")) != -1) {
		switch (opt) {
		/* General args */
		case 'U':
			pinned_file = optarg;
			break;
		case 'i':
			ifindex = atoi(optarg);
			break;
		default:
			usage();
		}
	}

	/*=load xdp bpf_object*/
	struct bpf_prog_load_attr prog_load_attr = {
        .prog_type	= BPF_PROG_TYPE_XDP,
    };
		
    prog_load_attr.file = "upf_kern.o";

    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &xdp_prog_fd);
    if (err) {
        printf("Does kernel support devmap lookup?\n");
        return 1;
    }
	
	map_pdr_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "m_teid_pdrs"));
	map_gtpu_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "m_psa_gtpu"));
	gtp_monitor_map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj, "gtp_monitor_map"));

    if (map_pdr_fd < 0 || map_gtpu_fd <0 || gtp_monitor_map_fd<0) {
		printf("map not found: %s or %s\n", strerror(map_pdr_fd), strerror(map_gtpu_fd));
		return 1;
	}

	err = do_attach(ifindex, xdp_prog_fd);
	if (err < 0){
		printf("prog dose not attach\n");
		return 1;
	}

    printf("qos user namespace start ...\n");
	array_fd = bpf_obj_get(pinned_file);
	if (array_fd < 0) {
		fprintf(stderr, "bpf_obj_get(%s): %s(%d)\n",
			pinned_file, strerror(errno), errno);
		return 1;
	}
	

	key = htonl(101058055); //src ip "6.6.6.7";
    val.bps = 1000 * num_kBps;
	val.t_last = 0;
	val.t_horizon_drop = 0.01 * val.bps;

	err = bpf_map_update_elem(array_fd, &key, &val, 0);
	if (err) {
		perror("bpf_map_update_elem1");
	}

    key = htonl(101058056); //"6.6.6.8";
    val.bps = 2000 * num_kBps;
	val.t_last = 0;
	val.t_horizon_drop = 0.01 * val.bps;

	err = bpf_map_update_elem(array_fd, &key, &val, 0);
	if (err) {
		perror("bpf_map_update_elem2");
	}

    printf("update map bpf\n");
	printf("load finish\n");

	err = bpf_map_lookup_elem(array_fd, &key, &val);
    if (err == 0)
    {
        // print the value
        printf("bps value read from the map: '%llu'\n", val.bps);
        printf("t_horizon_drop value read from the map: '%llu'\n", val.t_horizon_drop);
    }
    else
    {
        printf("Failed to read value from the map: %d (%s)\n", err, strerror(errno));
    }

	/* load pdr map for packet forward */
    // pdr info
    key =  htonl(0x01);
    char *pdr_src_mac = "9c:69:b4:60:90:22";
    mac_str_to_bin(pdr_src_mac, pdr1.src_mac);

    char *pdr_des_mac = "50:6b:4b:5c:66:e0";
    mac_str_to_bin(pdr_des_mac, pdr1.des_mac);

    pdr1.src_ip = htonl(180930664); //"10.200.200.104";
    pdr1.des_ip = htonl(180930662); //"10.200.200.102";
    pdr1.qfi = 9;

    err = bpf_map_update_elem(map_pdr_fd, &key, &pdr1, 0);
	if (err) {
		perror("bpf_map_update_elem");
	}

    key = htonl(0x01);
    char *psa_src_mac2 = "50:6b:4b:5c:66:e0";
    mac_str_to_bin(psa_src_mac2, psa_info.src_mac);

    char *psa_des_mac2 = "50:6b:4b:5c:69:d1";
    mac_str_to_bin(psa_des_mac2, psa_info.des_mac);

    psa_info.src_ip = htonl(180930662); //"10.200.200.102";
    psa_info.des_ip = htonl(180930663); //"10.200.200.103";
    psa_info.teid = htonl(0x01);

    err = bpf_map_update_elem(map_gtpu_fd, &key, &psa_info, 0);
	if (err) {
		perror("bpf_map_update_elem");
	}


    pdr2.src_ip = htonl(33686019); //"2.2.2.3";
    pdr2.des_ip = htonl(33686020); //"2.2.2.4";
    pdr2.qfi = 1;

    err = bpf_map_update_elem(map_pdr_fd, &key, &pdr2, 0);
	if (err) {
		perror("bpf_map_update_elem");
	}

    key = htonl(0x001e8480);
    char *psa_src_mac = "9c:69:b4:60:90:23";
    mac_str_to_bin(psa_src_mac, psa_info.src_mac);

    char *psa_des_mac = "9c:69:b4:60:90:66";
    mac_str_to_bin(psa_des_mac, psa_info.des_mac);

    psa_info.src_ip = htonl(117901063); //"7.7.7.7";
    psa_info.des_ip = htonl(117901064); //"7.7.7.8";
    psa_info.teid = htonl(0x001e8488);

    err = bpf_map_update_elem(map_gtpu_fd, &key, &psa_info, 0);
	if (err) {
		perror("bpf_map_update_elem");
	}

    key = htonl(0x001e8481);
    char *psa_src_mac3 = "9c:69:b4:60:90:23";
    mac_str_to_bin(psa_src_mac3, psa_info.src_mac);

    char *psa_des_mac3 = "9c:69:b4:60:90:66";
    mac_str_to_bin(psa_des_mac3, psa_info.des_mac);

    psa_info.src_ip = htonl(117901063); //"8.7.7.7";
    psa_info.des_ip = htonl(117901064); //"8.7.7.8";
    psa_info.teid = htonl(0x001e8489);

    err = bpf_map_update_elem(map_gtpu_fd, &key, &psa_info, 0);
	if (err) {
		perror("bpf_map_update_elem");
    }
    
    signal(SIGINT, int_exit);
    signal(SIGTERM, int_exit);

    return 0;
}
