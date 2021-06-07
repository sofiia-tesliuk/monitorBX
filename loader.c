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
#include <time.h>
#include <math.h>

#include <netdb.h>
#include <sys/socket.h>

#define BPF_ANY       0 /* create new element or update existing */

#define SLEEP_SECONDS 5

#define m 128
#define estimation_coef 11719 // a_m * m^2
#define pow_2_32 4294967296

typedef unsigned int u32;

//struct FileConfig{
//    int interface_index;
//    char* data_file;
//    bool count_distinct_mode;
//} fileConf;

struct ProgramConfig{
    int ifindex;
    FILE *data_f;
    int bpf_prog_fd;
    int ip_map_fd;
    int port_map_fd;
    int conf_map_fd;
    int values_map_fd;
    int registers_fd;
    bool count_distinct_mode;
    int sockfd;
} conf;

struct GeneralStats{
    int unique_ips;
    int unique_ports;
    int speed;
    int passed;
    int dropped;
    int tcp_n;
    int udp_n;
    int icmp_n;
    int other_n;
};

static volatile int keepRunning = 1;

void print_ip_info(FILE *f, u32 ip, int count){
    unsigned char bytes[4];
    bytes[0] = ip & 0xFF;
    bytes[1] = (ip >> 8) & 0xFF;
    bytes[2] = (ip >> 16) & 0xFF;
    bytes[3] = (ip >> 24) & 0xFF;

    fprintf(f, "\t%d.%d.%d.%d count: %d\n", bytes[0], bytes[1], bytes[2], bytes[3], count);
}

char* get_current_time(){
    time_t rawtime;
    struct tm * timeinfo;

    time (&rawtime);
    timeinfo = localtime (&rawtime);

    char* result = asctime(timeinfo);
    return result;
}

void print_general_stats(struct GeneralStats stats){
    char buff[1024];
    bzero(buff, sizeof(buff));
    int s = sprintf(buff,
                  "Time:                        %s"
                  "Speed:                       %.2f\n"
                  "Packets passed:              %d\n"
                  "Packets dropped:             %d\n"
                  "Packets with TCP protocol:   %d\n"
                  "Packets with UDP protocol:   %d\n"
                  "Packets with ICMP protocol:  %d\n"
                  "Packets with Other protocol: %d\n"
                  "Unique IPs:                  %d\n"
                  "Unique PORTs:               %d\n\n",
                  get_current_time(), ((float) stats.speed) / SLEEP_SECONDS, stats.passed, stats.dropped,
            stats.tcp_n, stats.udp_n, stats.icmp_n, stats.other_n, stats.unique_ips, stats.unique_ports);
    buff[s] = '\0';
    printf("%s", buff);

    fprintf(conf.data_f, "%s", buff);

    if (conf.sockfd != -1){
        char buff_size[2];
        buff_size[0] = (char)(s + 1);
        buff_size[1] = '\0';
        write(conf.sockfd, buff_size, sizeof(buff_size));
        write(conf.sockfd, buff, s + 1);
    }
}


void terminate(int dummy){
    keepRunning = 0;
}


int bpf_init(char *bpf_filename){
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

    printf("The kernel loaded the BPF program\n");

    if (conf.count_distinct_mode){
        char *registers_map = "registers";
        conf.registers_fd = bpf_object__find_map_fd_by_name(obj, registers_map);
        printf("Registers map fd is: %d\n", conf.registers_fd);
    }else{
        char *conf_map = "conf_map";
        conf.conf_map_fd = bpf_object__find_map_fd_by_name(obj, conf_map);
        printf("Conf map fd is: %d\n", conf.conf_map_fd);

        char *values_map = "values_map";
        conf.values_map_fd = bpf_object__find_map_fd_by_name(obj, values_map);
        printf("Values map fd is: %d\n", conf.values_map_fd);

        char *ip_map = "ip_map";
        conf.ip_map_fd = bpf_object__find_map_fd_by_name(obj, ip_map);
        printf("IP map fd is: %d\n", conf.ip_map_fd);

        char *port_map = "port_map";
        conf.port_map_fd = bpf_object__find_map_fd_by_name(obj, port_map);
        printf("PORT map fd is: %d\n", conf.port_map_fd);
    }

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
    u32 key, next_key;
    int value;
    int err, unique_ips, unique_ports;
    int i = 0;
    while(keepRunning){
        unique_ips = 0;
        unique_ports = 0;
        key = 0;
        while (bpf_map_get_next_key(conf.ip_map_fd, &key, &next_key) == 0){
            err = bpf_map_lookup_elem(conf.ip_map_fd, &next_key, &value);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "lookup value with key (%d) failed (%d): %s\n",
                        next_key, -err, strerror(-err));
            }
            err = bpf_map_delete_elem(conf.ip_map_fd, &next_key);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "delete value with key (%d) failed (%d): %s\n",
                        next_key, -err, strerror(-err));
            }
            unique_ips += 1;
//            print_ip_info(conf.data_f, next_key, value);
            key = next_key;
        }

        key = 0;
        while (bpf_map_get_next_key(conf.port_map_fd, &key, &next_key) == 0){
            err = bpf_map_lookup_elem(conf.port_map_fd, &next_key, &value);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "lookup value with key (%d) failed (%d): %s\n",
                        next_key, -err, strerror(-err));
            }
            err = bpf_map_delete_elem(conf.port_map_fd, &next_key);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "delete value with key (%d) failed (%d): %s\n",
                        next_key, -err, strerror(-err));
            }
            unique_ports += 1;
            fprintf(conf.data_f, "\t%d count: %d\n", next_key, value);
            key = next_key;
        }

        struct GeneralStats newStats;
        key = 0;
        value = 0;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.passed);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of passed packets (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of passed packets (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        key = 1;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.dropped);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of dropped packets (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of dropped packets (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        key = 2;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.speed);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup size (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop size (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        key = 3;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.tcp_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets tcp protocol (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of packets tcp protocol (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        key = 4;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.udp_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with udp protocol (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of packets with udp protocol (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        key = 5;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.icmp_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with icmp protocol (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with icmp protocol (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        key = 6;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.other_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with other protocol (%d) failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with other protocol (%d) to zero failed (%d): %s\n",
                    next_key, -err, strerror(-err));
        }

        newStats.unique_ips = unique_ips;
        newStats.unique_ports = unique_ports;

        print_general_stats(newStats);

        sleep(SLEEP_SECONDS);
        i += 1;
    }

    return 0;
}

int count_distinct_ip_addresses(){
    int i = 0;
    int value, err, pow, v;
    float hyperLogLogEstimate, linearCountingEstimate, linearCountingEstimateH;
    while(keepRunning){
        hyperLogLogEstimate = 0;
        v = 0;
        // i < 128 -- size of array registers
        for (int j = 0; j < m; j++){
            err = bpf_map_lookup_elem(conf.registers_fd, &j, &value);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "lookup value with key (%d) failed (%d): %s\n",
                        j, -err, strerror(-err));
            }
//            fprintf(conf.data_f, "\ti: %d; value: %d", j, value);
//            printf("\ti: %d - value: %d;", j, value);
            if (value > 0.1){
                pow = 1;
                for (int k = 0; k < value; k++){
                    pow *= 2;
                }
                hyperLogLogEstimate += 1 / ((float) pow);
            } else{
                v += 1;
            }
        }

        if (hyperLogLogEstimate > 0.1){
            hyperLogLogEstimate = 1 / hyperLogLogEstimate;
        }

        pow = 128;
        err = bpf_map_lookup_elem(conf.registers_fd, &pow, &value);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of received packets failed (%d): %s\n",
                    -err, strerror(-err));
        }

        linearCountingEstimate = ((double) m) * log(((double)m) / v);
        linearCountingEstimateH = log(1 - (hyperLogLogEstimate / ((float) pow_2_32))) * (-1) * ((float) pow_2_32);

        fprintf(conf.data_f, "\nTime: %sReceived packets: %d\nHyperLogLog Estimate: %f\nLinear Counting Estimate: %f\tV: %d\nHyper Linear Counting Estimate: %f\n",
                get_current_time(), value, estimation_coef * hyperLogLogEstimate, linearCountingEstimate, v, linearCountingEstimateH);
        printf("\nTime: %sReceived packets: %d\nHyperLogLog Estimate: %f\nLinear Counting Estimate: %f\tV: %d\nHyper Linear Counting Estimate: %f\n",
                get_current_time(), value, estimation_coef * hyperLogLogEstimate, linearCountingEstimate, v, linearCountingEstimateH);
        sleep(SLEEP_SECONDS);
        i += 1;
    }

    return 0;
}


int main(int argc, char **argv) {
    char *data_file = "net.dat";
    char *chart_server_ip = "192.168.99.1";
    int chart_server_port = 8080;
    char *chart_server_port_char = NULL;
    char *ifindex_char = NULL;
    int c, err;
    conf.count_distinct_mode = false;

    while ((c = getopt(argc, argv, "hci:f:s:p:")) != -1){
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
            case 'c':
                conf.count_distinct_mode = true;
                break;
            case 's':
                chart_server_ip = optarg;
            case 'p':
                chart_server_port_char = optarg;
                chart_server_port = atoi(chart_server_port_char);
                if (chart_server_port == 0){
                    fprintf(stderr, "ERROR: Invalid port of chart server: %d.\n", chart_server_port);
                    return -1;
                }
                break;
            case 'h':
                printf("-h Help\n-i Index of network interface\n-f Filename of saved data\n-c Count distinct mode\n");
                return 0;
        }
    }

    int connfd;
    struct sockaddr_in servaddr, cli;

    // socket create and verification
    conf.sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (conf.sockfd == -1) {
        printf("socket creation failed...\n");
        exit(0);
    }
    else
        printf("Socket successfully created..\n");
    bzero(&servaddr, sizeof(servaddr));

    // assign IP, PORT
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = inet_addr(chart_server_ip);
    servaddr.sin_port = htons(chart_server_port);

    // connect the client socket to server socket
    if (connect(conf.sockfd, (struct sockaddr*)&servaddr, sizeof(servaddr)) != 0) {
        printf("connection with the server failed...\n");
        exit(0);
    }
    else
        printf("connected to the server..\n");


    // Opening data file
    conf.data_f = fopen(data_file, "a");
    if (!conf.data_f){
        fprintf(stderr, "ERROR: Unable to open file: %s.\n", data_file);
        return -2;
    }

    if (conf.count_distinct_mode){
        err = bpf_init("bpf_count_distinct.o");
    }else{
        err = bpf_init("bpf_program.o");
    }
    if (err != 0){
        fprintf(stderr, "ERROR: Failed to init BPF: %d.\n", err);
        return -3;
    }

    signal(SIGINT, terminate);

    if (conf.count_distinct_mode){
        count_distinct_ip_addresses();
    }else{
        collect_general_info();
    }
    printf("Program is terminated\n");

    fclose(conf.data_f);

    close(conf.bpf_prog_fd);

    close(conf.sockfd);

    return 0;
}
