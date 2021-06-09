#define KBUILD_MODNAME "xdp_monitorbx"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#include "bpf_includes.h"

#ifdef BPF_TRACE_CUSTOM
#define custom_trace_printk(fmt,...) bpf_trace_printk(fmt, ##__VA_ARGS__)
#else
#define custom_trace_printk(fmt,...)
#endif


// 0 -- save packets
// 1 -- drop all packets
struct bpf_map_def SEC("maps") conf_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 2,
        .map_flags   = 0
};


// 0 - Number of passed packets
// 1 - Number of dropped packets
// 2 - Size
// 3 - Number with TCP protocol
// 4 - Number with UDP protocol
// 5 - Number with ICMP protocol
// 6 - Number with Other protocol
struct bpf_map_def SEC("maps") values_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 7,
        .map_flags   = 0
};


struct bpf_map_def SEC("maps") ip_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 100,
        .map_flags   = 0
};


struct bpf_map_def SEC("maps") port_map = {
        .type        = BPF_MAP_TYPE_HASH,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 20,
        .map_flags   = 0
};

struct bpf_map_def SEC("maps") registers = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(int),
        .value_size  = sizeof(int),
        .max_entries = 128,
};

static int hashing(int ip){
    int h = ((ip & 0xFF) << 24) + (((ip >> 8) & 0xFF) << 16) + (((ip >> 16) & 0xFF) << 8) + (((ip >> 24) & 0xFF));
    return (h * 2654435761) % 4294967296;
}

// Index of left most 1
static int rank(int hash){
    int r = 0;
    while (((hash & 1) == 0) && (r < (32 - p_bits))){
        r++;
        hash >>= 1;
    }
    return r+1;
}

// Number out of first log_2_m bits
static int register_index(int hash){
    int index = 0;
    index = (hash >> (32 - p_bits));
    return index & (m-1);
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
int xdp_monitorbx(struct xdp_md *ctx)
{
    int XDP_ACTION = XDP_PASS;
    int index = 0;
    int *value;

    // Check if dropping packets is enabled
    int *drop_all_packets;
    drop_all_packets = bpf_map_lookup_elem(&conf_map, &index);
    if (drop_all_packets) {
        if (*drop_all_packets == 1){
            XDP_ACTION = XDP_DROP;
            index = 1;
        }
    }

    // Update number of Passed/Dropped packets
    value = bpf_map_lookup_elem(&values_map, &index);
    if (value){
        *value += 1;
    } else{
        char errmsg[] = "Failed to update number of passed/dropped packets";
        custom_trace_printk(errmsg, sizeof(errmsg));
    }

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Update size
    index = 2;
    value = bpf_map_lookup_elem(&values_map, &index);
    if (value){
        *value += data_end - data;
    }else{
        char errmsg[] = "Failed to update size";
        custom_trace_printk(errmsg, sizeof(errmsg));
    }

    // check packet size
    if (eth + 1 > data_end) {
        return XDP_ACTION;
    }

    // check if the packet is an IP packet
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return XDP_ACTION;
    }

    // get the source address of the packet
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end) {
        return XDP_ACTION;
    }

    // Trace message about received packet
    char msg[] = "IP address is %u";
    custom_trace_printk(msg, sizeof(msg), iph->saddr);

    // Increase counter for source IP
    int *result;
    result = bpf_map_lookup_elem(&ip_map, &(iph->saddr));
    if (result)
        *result += 1;
    else{
        index = 1;
        int err = bpf_map_update_elem(&ip_map, &(iph->saddr), &index, BPF_NOEXIST);
        if (err != 0){
            char errmsg[] = "Failed to add element to ip map %u, error code %d";
            custom_trace_printk(errmsg, sizeof(errmsg), iph->saddr, err);
        }
    }

    // Trace message about received packet
    char msg_h[] = "Hash is %s; rank: %d; register index: %d"; // bpf_trace_printk doesn't allow more than 5 arguments
    int h = hashing(iph->saddr);
    int r = rank(h);
    index = register_index(h);

    custom_trace_printk(msg_h, sizeof(msg_h), binary_hash(h), r, index);

    // Set register for source IP address
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


    u32 dest_port = 0;
    // Identify the protocol of the packet
    if (iph->protocol == IPPROTO_TCP){
        index = 3;
        struct tcphdr *tcp = (void*)iph + sizeof(*iph);
        if (tcp + 1 > data_end){
            return XDP_ACTION;
        }
        dest_port = tcp->dest;
    } else if (iph->protocol == IPPROTO_UDP){
        index = 4;
        struct udphdr *udp = (void*)iph + sizeof(*iph);
        if (udp + 1 > data_end){
            return XDP_ACTION;
        }
        dest_port = udp->dest;
    } else if (iph->protocol == IPPROTO_ICMP){
        index = 5;
    } else{
        index = 6;
    }

    // Update counter of protocol
    value = bpf_map_lookup_elem(&values_map, &index);
    if (value){
        *value += 1;
    }else{
        char errmsg[] = "Failed to update protocol counter";
        custom_trace_printk(errmsg, sizeof(errmsg));
    }

    if (dest_port > 0){
        // Increase counter for destination PORT
        result = bpf_map_lookup_elem(&port_map, &dest_port);
        if (result)
            *result += 1;
        else{
            index = 1;
            int err = bpf_map_update_elem(&port_map, &dest_port, &index, BPF_NOEXIST);
            if (err != 0){
                char errmsg[] = "Failed to add element to port map %u, error code %d";
                custom_trace_printk(errmsg, sizeof(errmsg), dest_port, err);
            }
        }
    }

    return XDP_ACTION;
}

char _license[] SEC("license") = "GPL";