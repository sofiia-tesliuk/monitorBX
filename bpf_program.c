#define KBUILD_MODNAME "xdp_ip_address"

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <netinet/in.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <linux/if_vlan.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/udp.h>

#define BPF_NOEXIST   1 /* create new element only if it didn't exist */

#ifdef BPF_TRACE_CUSTOM
#define custom_trace_printk(fmt,...) bpf_trace_printk(fmt, ##__VA_ARGS__)
#else
#define custom_trace_printk(fmt,...)
#endif

typedef unsigned int u32;

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
// 5 - Number with Other protocol
struct bpf_map_def SEC("maps") values_map = {
        .type        = BPF_MAP_TYPE_ARRAY,
        .key_size    = sizeof(u32),
        .value_size  = sizeof(int),
        .max_entries = 6,
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


SEC("tx")
int xdp_tx(struct xdp_md *ctx)
{
    int xdp_action = XDP_PASS;
    int index = 0;
    int *value;

    // Check if dropping packets is enabled
    int *drop_all_packets;
    drop_all_packets = bpf_map_lookup_elem(&conf_map, &index);
    if (drop_all_packets) {
        if (*drop_all_packets == 1){
            xdp_action = XDP_DROP;
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

    //TODO: pass the whole packet

    void *data_end = (void *)(long)ctx->data_end;
    void *data     = (void *)(long)ctx->data;
    struct ethhdr *eth = data;

    // Update size
    index = 2;
    value = bpf_map_lookup_elem(&values_map, &index);
    if (value){
        *value += sizeof(ctx);
    }else{
        char errmsg[] = "Failed to update size";
        custom_trace_printk(errmsg, sizeof(errmsg));
    }

    // check packet size
    if (eth + 1 > data_end) {
        return xdp_action;
    }

    // check if the packet is an IP packet
    if (ntohs(eth->h_proto) != ETH_P_IP) {
        return xdp_action;
    }

    // get the source address of the packet
    struct iphdr *iph = data + sizeof(struct ethhdr);
    if (iph + 1 > data_end) {
        return xdp_action;
    }

    // Trace message about received packet
    char msg[] = "Hello, ip address is %u";
    custom_trace_printk(msg, sizeof(msg), iph->saddr);

    // Increase counter for source IP
    int *result;
    result = bpf_map_lookup_elem(&ip_map, &(iph->saddr));
    if (result)
        *result += 1;
    else{
        *value = 1;
        int err = bpf_map_update_elem(&ip_map, &(iph->saddr), &value, BPF_NOEXIST);
        if (err != 0){
            char errmsg[] = "Failed to add element to ip map %u, error code %d";
            custom_trace_printk(errmsg, sizeof(errmsg), iph->saddr, err);
        }
    }

    u32 dest_port = 0;
    // Identify the protocol of the packet
    if (iph->protocol == IPPROTO_TCP){
        index = 3;
        struct tcphdr *tcp = (void*)iph + sizeof(*iph);
        dest_port = tcp->dest;
    } else if (iph->protocol == IPPROTO_UDP){
        index = 4;
        struct udphdr *udp = (void*)iph + sizeof(*iph);
        dest_port = udp->dest;
    } else{
        index = 5;
    }

    // Update counter of protocol
    value = bpf_map_lookup_elem(&values_map, &index);
    if (value){
        *value += 1;
    }else{
        char errmsg[] = "Failed to protocol counter";
        custom_trace_printk(errmsg, sizeof(errmsg));
    }

    if (dest_port){
        // Increase counter for destination PORT
        result = bpf_map_lookup_elem(&port_map, &dest_port);
        if (result)
            *result += 1;
        else{
            *value = 1;
            int err = bpf_map_update_elem(&port_map, &dest_port, &value, BPF_NOEXIST);
            if (err != 0){
                char errmsg[] = "Failed to add element to port map %u, error code %d";
                custom_trace_printk(errmsg, sizeof(errmsg), dest_port, err);
            }
        }
    }

    return xdp_action;
}

char _license[] SEC("license") = "GPL";