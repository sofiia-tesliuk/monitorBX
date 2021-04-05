#define KBUILD_MODNAME "xdp_ip_address"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

#define BPF_NOEXIST   1 /* create new element only if it didn't exist */

typedef unsigned int u32;

struct bpf_map_def SEC("maps") ip_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 10,
        .map_flags   = 0
};

static inline void trace_ip(u32 ip){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    char msg[] = "Hello, ip address is x.%d.%d.%d"; // bpf_trace_printk doesn't allow more than 5 arguments
    bpf_trace_printk(msg, sizeof(msg), bytes[1], bytes[2], bytes[3]);
}

SEC("tx")
int xdp_tx(struct xdp_md *ctx)
{
    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // check packet size
    if (eth + 1 > data_end) {
        return XDP_PASS;
    }

    // check if the packet is an IP packet
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_PASS;
    }

    // get the source address of the packet
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end) {
        return XDP_PASS;
    }

    #ifdef BPF_TRACE_CUSTOM
    // Trace message about received packet
    trace_ip(iph->saddr);
    #endif

    // Increase counter
    int *result;
    result = bpf_map_lookup_elem(&ip_map, &(iph->saddr));
    if (result)
        *result += 1;
    else{
        int value = 1;
        int err = bpf_map_update_elem(&ip_map, &(iph->saddr), &value, BPF_NOEXIST);
        #ifdef BPF_TRACE_CUSTOM
        if (err != 0){
            char errmsg[] = "Failed to add element to map %u, error code %d";
            bpf_trace_printk(errmsg, sizeof(errmsg), iph->saddr, err);
        }
        #endif
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";