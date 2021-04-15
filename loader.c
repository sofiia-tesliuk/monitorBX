#include <libbpf.h> /* /usr/include/bpf/libbpf.h */
#include <bpf.h>
#include <stdio.h>
#include <unistd.h>

#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>

#include <bpf/bpf.h>
#include <bpf/libbpf.h>

#include <net/if.h>
#include <linux/if_link.h>

#include <signal.h>

#define SLEEP_SECONDS 5

typedef unsigned int u32;

struct Config{
    int ifindex;
    FILE *data_f;
    int bpf_prog_fd;
    int map_fd;
} conf;

static volatile int keepRunning = 1;

void print_ip_info(FILE *f, u32 ip, int count){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    fprintf(f, "\t%d.%d.%d.%d count: %d\n", bytes[0], bytes[1], bytes[2], bytes[3], count);
}


void terminate(int dummy){
    keepRunning = 0;
}


int bpf_init(char *bpf_filename, char *map_name){
    struct bpf_object *obj;
    int err, prog_fd;

    err = bpf_prog_load(bpf_filename, BPF_PROG_TYPE_XDP, &obj, &conf.bpf_prog_fd);
    if (err < 0) {
        fprintf(stderr, "ERROR: "
                        "bpf program load failed (%d): %s\n",
                        -err, strerror(-err));
        return -1;
    }else{
        printf("err: %d, prog_fd: %d\n", err, conf.bpf_prog_fd); // Noticed that err (that supposed to be fd of bpf program and prog_fd are different.)
    }

    conf.map_fd = bpf_object__find_map_fd_by_name(obj, map_name);
    printf("Map fd is: %d\n", conf.map_fd);

    err = bpf_set_link_xdp_fd(conf.ifindex, conf.bpf_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);
    if (err < 0) {
        fprintf(stderr, "ERROR: "
                        "ifindex(%d) link set xdp fd failed (%d): %s\n",
                        conf.ifindex, -err, strerror(-err));
        return -2;
    }
    return 0;
}


int collect_general_info(){
    u32 key;
    u32 next_key;
    int value, err;
    int i = 0;
    while(keepRunning){
        fprintf(conf.data_f, "Cycle %d\n", i);
        printf("Cycle %d\n", i);
        key = 0;
        while (bpf_map_get_next_key(conf.map_fd, &key, &next_key) == 0){
            err = bpf_map_lookup_elem(conf.map_fd, &next_key, &value);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "lookup value with key (%d) failed (%d): %s\n",
                        next_key, -err, strerror(-err));
            }
            print_ip_info(conf.data_f, next_key, value);
            key = next_key;
        }

        sleep(SLEEP_SECONDS);
        i += 1;
    }
}


int main(int argc, char **argv) {
    char *data_file = "net.dat";
    char *ifindex_char = NULL;
    int c, err;

    while ((c = getopt(argc, argv, "hi:f:")) != -1){
        switch (c){
            case 'i':
                ifindex_char = optarg;
                conf.ifindex = atoi(ifindex_char);
                if (conf.ifindex == 0){
                    fprintf(stderr, "ERROR: Invalid index of network device: %s.\n", ifindex_char);
                    return -1;
                }
                break;
            case 'f':
                data_file = optarg;
                break;
            case 'h':
                printf("-h Help\n-i Index of network interface\n-f Filename of saved data\n");
                break;
        }
    }

    // Opening data file
    conf.data_f = fopen(data_file, "a");
    if (!conf.data_f){
        fprintf(stderr, "ERROR: Unable to open file: %s.\n", data_file);
        return -2;
    }

    // TODO: add an option to load bpf program for collecting reduced information

    err = bpf_init("bpf_program.o", "ip_map");
    if (err != 0){
        fprintf(stderr, "ERROR: Failed to init BPF: %d.\n", err);
        return -3;
    }

    printf("The kernel loaded the BPF program\n");

    signal(SIGINT, terminate);

    // TODO: call function that collects reduced information
    collect_general_info();
    printf("Program is terminated");

    fclose(conf.data_f);

    // TODO: take a look why it doesn't offload bpf program
    close(conf.bpf_prog_fd);

    return 0;
}
