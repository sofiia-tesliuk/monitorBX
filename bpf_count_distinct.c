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

struct bpf_map_def SEC("maps") registers = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(int),
        .value_size  = sizeof(int),
        // 128 + 1 (for total number fo packets)
        .max_entries = 129,
};

#define log_2_m 7

static int hashing(int ip){
    int h = ((ip & 0xFF) << 24) + (((ip >> 8) & 0xFF) << 16) + (((ip >> 16) & 0xFF) << 8) + (((ip >> 24) & 0xFF));
    return (h * 2654435761) % 4294967296;
}

// Index of left most 1
static int rank(int hash){
    int r = 1;
    while (((hash & 1) == 0) && (r <= (32 - log_2_m))){
        r++;
        hash >>= 1;
    }
    return r;
}

// Number out of first m bits
static int register_index(int hash){
    int index = 0;
    for (int i = 0; i < log_2_m; i++){
        index <<= 1;
        index += (hash >> (32 - i)) & 1;
    }

    return index;
}

// Hash in binary string
static char* binary_hash(int h){
    char b[32] = {0};
    for (int i = 0; i < 32; i++){
        b[31 - i] = (h >> i) & 1 ? '1': '0';
    }
    return b;
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

    // Trace message about received packet
    char msg[] = "Hello, hash is %s; rank: %d; register index: %d"; // bpf_trace_printk doesn't allow more than 5 arguments
    int h = hashing(iph->saddr);
    int r = rank(h);
    int index = register_index(h);

    custom_trace_printk(msg, sizeof(msg), binary_hash(h), r, index);

    // Set register
    int *result;
    result = bpf_map_lookup_elem(&registers, &index);
    if (result)
        *result = (*result > r) ? *result : r;
    else{
        int err = bpf_map_update_elem(&registers, &index, &r, BPF_NOEXIST);
        if (err != 0){
            char errmsg[] = "Failed to add element to map with index %d, error code %d";
            custom_trace_printk(errmsg, sizeof(errmsg), index, err);
        }
    }

    // Increase number of packets
    index = 128;
    result = bpf_map_lookup_elem(&registers, &index);
    if (result)
        *result += 1;
    else{
        char errmsg[] = "Failed to increase number of packets, 'result' %d";
        custom_trace_printk(errmsg, sizeof(errmsg), result);
    }

    return XDP_PASS;
}

char _license[] SEC("license") = "GPL";