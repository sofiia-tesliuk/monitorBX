#define KBUILD_MODNAME "xdp_ip_address"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>

#define BPF_NOEXIST   1 /* create new element only if it didn't exist */

#ifdef BPF_TRACE_CUSTOM
#define custom_trace_printk(fmt,...) bpf_trace_printk(fmt, ##__VA_ARGS__)
#else
#define custom_trace_printk(fmt,...)
#endif

typedef unsigned int u32;

struct bpf_map_def SEC("maps") ip_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 100,
        .map_flags   = 0
};


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

    // Trace message about received packet
    char msg[] = "Hello, ip address is %u"; // bpf_trace_printk doesn't allow more than 5 arguments
    custom_trace_printk(msg, sizeof(msg), iph->saddr);

    // Increase counter
    int *result;
    result = bpf_map_lookup_elem(&ip_map, &(iph->saddr));
    if (result)
        *result += 1;
    else{
        int value = 1;
        int err = bpf_map_update_elem(&ip_map, &(iph->saddr), &value, BPF_NOEXIST);
        if (err != 0){
            char errmsg[] = "Failed to add element to map %u, error code %d";
            custom_trace_printk(errmsg, sizeof(errmsg), iph->saddr, err);
        }
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";