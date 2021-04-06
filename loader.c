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

#define SLEEP_SECONDS 5

typedef unsigned int u32;

void print_ip_info(u32 ip, int count){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    printf("\t%d.%d.%d.%d count: %d\n", bytes[0], bytes[1], bytes[2], bytes[3], count);
}

int main(int argc, char **argv) {
    const char *file = "bpf_program.o";
    struct bpf_object *obj;
    int err, prog_fd, map_fd;

    err = bpf_prog_load(file, BPF_PROG_TYPE_XDP, &obj, &prog_fd);
    if (err < 0) {
        fprintf(stderr, "ERROR: "
                        "bpf program load failed (%d): %s\n",
                -err, strerror(-err));
        return -1;
    }

    map_fd = bpf_object__find_map_fd_by_name(obj, "ip_map");
    printf("Map fd is: %d\n", map_fd);

    int ifindex = 3;
    err = bpf_set_link_xdp_fd(ifindex, prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);
    if (err < 0) {
        fprintf(stderr, "ERROR: "
                        "ifindex(%d) link set xdp fd failed (%d): %s\n",
                ifindex, -err, strerror(-err));
        return -2;
    }

    printf("The kernel loaded the BPF program\n");

    sleep(SLEEP_SECONDS);

    u32 key;
    u32 next_key;
    int value;
    for(int i = 0; i < 100; i++){
        printf("Cycle %d\n", i);
        key = 42;
        while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0){
            err = bpf_map_lookup_elem(map_fd, &next_key, &value);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "lookup value with key (%d) failed (%d): %s\n",
                        next_key, -err, strerror(-err));
            }
            print_ip_info(next_key, value);
            key = next_key;
        }

        sleep(SLEEP_SECONDS);
    }


    return 0;
}
