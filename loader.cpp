#include <libbpf.h> /* /usr/include/bpf/libbpf.h */
#include <bpf.h>
#include <stdio.h>
#include <unistd.h>
#include <iostream>
#include <queue>

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
#include <cmath>

#include <netdb.h>
#include <sys/socket.h>
#include <arpa/inet.h>

#include "bpf_includes.h"

#define comparisonMultiplier 10


struct ProgramConfig{
    int ifindex;
    FILE *data_f;
    int bpf_prog_fd;
    int ip_map_fd;
    int port_map_fd;
    int conf_map_fd;
    int values_map_fd;
    int registers_fd;
    bool socket_data_provider;
    int server_port;
    std::string server_ip;
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
    int average_count_per_ip;
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

void provide_general_stats(struct GeneralStats stats){
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
                  "Unique PORTs:                %d\n\n",
                  get_current_time(), ((float) stats.speed) / SLEEP_SECONDS, stats.passed, stats.dropped,
            stats.tcp_n, stats.udp_n, stats.icmp_n, stats.other_n, stats.unique_ips, stats.unique_ports);
    buff[s] = '\0';
    printf("%s", buff);
    fprintf(conf.data_f, "%s", buff);

    char buff_size[2];
    buff_size[1] = '\0';
    if (conf.socket_data_provider) {
        buff_size[0] = (char) (s + 1);
        send(conf.sockfd, buff_size, sizeof(buff_size), 0);
        send(conf.sockfd, buff, s + 1, 0);
    }

//    while(!msgs.empty()){
//        s = sprintf(buff, "Message: %s\n", msgs.front());
//        msgs.pop();
//        buff[s] = '\0';
//        printf("%s", buff);
//        fprintf(conf.data_f, "%s", buff);
//
//        if (conf.socket_data_provider){
//            buff_size[0] = (char)(s + 1);
//            send(conf.sockfd, buff_size, sizeof(buff_size), 0);
//            send(conf.sockfd, buff, s + 1, 0);
//        }
//    }
}

void terminate(int dummy){
    keepRunning = 0;
}


int socket_data_provider_init(){
    // Server configuration
    int server_socket = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (server_socket == -1){
        fprintf(stderr, "SERVER: Failed to create socket.");
        close(server_socket);
        return -1;
    }

    // Bind some address
    struct sockaddr_in addr = {0};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(8080);

    char ip[conf.server_ip.length() + 1];
    strcpy(ip, conf.server_ip.c_str());

    char* ip_address = "192.168.99.157";
    addr.sin_addr.s_addr = inet_addr(ip_address);

    if (bind(server_socket, (struct sockaddr*) &addr, sizeof(addr)) == -1){
        fprintf(stderr, "SERVER: Unable to bind address. IP address: %s", conf.server_ip);
        close(server_socket);
        return -2;
    }

    printf("Bind address");

    // Listen
    if (listen(server_socket, 1) == -1) {
        fprintf(stderr, "SERVER: Failed to listen.");
        close(server_socket);
        return -3;
    }


    int client_socket;
    uint16_t message_length;


    printf("Connection try: ");

    // Accept connection
    socklen_t socklen = sizeof addr;
    client_socket = accept(server_socket, (struct sockaddr *) &addr, &socklen);
    if (client_socket == -1) {
        fprintf(stderr, "SERVER: Failed to accept.");
        return -4;
    }
    conf.sockfd = client_socket;
    return 0;
}


int bpf_init(){
    char bpf_filename[] = "bpf_program.o";
    struct bpf_object *obj;
    int err, prog_fd;

    err = bpf_prog_load(bpf_filename, BPF_PROG_TYPE_XDP, &obj, &conf.bpf_prog_fd);
    if (err < 0) {
        fprintf(stderr, "ERROR: "
                        "bpf program load failed (%d): %s\n",
                        -err, strerror(-err));
        return -1;
    } else {
        printf("err: %d, prog_fd: %d\n", err, conf.bpf_prog_fd); // Noticed that err (that supposed to be fd of bpf program and prog_fd are different.)
    }

    printf("The kernel loaded the BPF program\n");

    // Maps lookup
    char conf_map[] = "conf_map";
    conf.conf_map_fd = bpf_object__find_map_fd_by_name(obj, conf_map);
    printf("Conf map fd is: %d\n", conf.conf_map_fd);

    char values_map[] = "values_map";
    conf.values_map_fd = bpf_object__find_map_fd_by_name(obj, values_map);
    printf("Values map fd is: %d\n", conf.values_map_fd);

    char ip_map[] = "ip_map";
    conf.ip_map_fd = bpf_object__find_map_fd_by_name(obj, ip_map);
    printf("IP map fd is: %d\n", conf.ip_map_fd);

    char port_map[] = "port_map";
    conf.port_map_fd = bpf_object__find_map_fd_by_name(obj, port_map);
    printf("PORT map fd is: %d\n", conf.port_map_fd);

    char registers_map[] = "registers";
    conf.registers_fd = bpf_object__find_map_fd_by_name(obj, registers_map);
    printf("Registers map fd is: %d\n", conf.registers_fd);

    // Attaching program to network interface
    err = bpf_set_link_xdp_fd(conf.ifindex, conf.bpf_prog_fd, XDP_FLAGS_UPDATE_IF_NOEXIST | XDP_FLAGS_SKB_MODE);
    if (err < 0) {
        fprintf(stderr, "ERROR: "
                        "ifindex(%d) link set xdp fd failed (%d): %s\n",
                        conf.ifindex, -err, strerror(-err));
        return -2;
    }
    return 0;
}


int collect_info(){
    u32 key, next_key;
    int value, err, pow, v;
    int unique_ips, unique_ports, sum_count_ips, sum_count_ports, avg_unique_ips, avg_unique_ports, avg_count_per_ip;
    float avg_speed;
    double estimate;

    std::queue<int> unique_ips_q, unique_ports_q, count_per_ip_q, speed_q;
    avg_unique_ips = 0;
    avg_unique_ports = 0;
    avg_count_per_ip = 0;
    avg_speed = 0;

    for (int i = 0; i < k_neighbors; i++){
        unique_ips_q.push(0);
        unique_ports_q.push(0);
        count_per_ip_q.push(0);
        speed_q.push(0);
    }

    while(keepRunning){
        struct GeneralStats newStats;
//        std::queue <std::string> logs;

        // ESTIMATE

        estimate = 0;
        for (int j = 0; j < m; j++){
            err = bpf_map_lookup_elem(conf.registers_fd, &j, &value);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "lookup value with key (%d) failed (%d): %s\n",
                        j, -err, strerror(-err));
            }
            estimate += std::pow(2, -value);
            value = 0;
            err = bpf_map_update_elem(conf.registers_fd, &j, &value, BPF_ANY);
            if (err < 0){
                fprintf(stderr, "ERROR: "
                                "delete value with key (%d) failed (%d): %s\n",
                        j, -err, strerror(-err));
            }
        }

        if (estimate > 0.1){
            estimate = estimation_coef / estimate;
        }

        // GENERAL STATS
        key = 0;
        value = 0;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.passed);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of passed packets (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of passed packets (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }

        key = 1;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.dropped);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of dropped packets (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of dropped packets (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }

        key = 2;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.speed);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup size (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop size (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        if (newStats.speed > (comparisonMultiplier * (avg_speed / k_neighbors))){
//            logs.push("Anomaly increase of data transfer rate.");
            printf("Anomaly increase of data transfer rate.\n");
        }
        avg_speed += newStats.speed;
        speed_q.push(newStats.speed);
        avg_speed -= speed_q.front();
        speed_q.pop();

        key = 3;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.tcp_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets tcp protocol (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of packets tcp protocol (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }

        key = 4;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.udp_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with udp protocol (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "drop number of packets with udp protocol (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }

        key = 5;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.icmp_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with icmp protocol (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with icmp protocol (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }

        key = 6;
        err = bpf_map_lookup_elem(conf.values_map_fd, &key, &newStats.other_n);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with other protocol (%d) failed (%d): %s\n",
                    key, -err, strerror(-err));
        }
        err = bpf_map_update_elem(conf.values_map_fd, &key, &value, BPF_ANY);
        if (err < 0){
            fprintf(stderr, "ERROR: "
                            "lookup number of packets with other protocol (%d) to zero failed (%d): %s\n",
                    key, -err, strerror(-err));
        }


        // IP PORT DISTRIBUTION

        unique_ips = 0;
        unique_ports = 0;
        sum_count_ips = 0;
        sum_count_ports = 0;

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
            sum_count_ips += value;
            if (value > (comparisonMultiplier * (avg_count_per_ip / k_neighbors))){
                char buff[16];
                unsigned char bytes[4];
                bytes[0] = key & 0xFF;
                bytes[1] = (key >> 8) & 0xFF;
                bytes[2] = (key >> 16) & 0xFF;
                bytes[3] = (key >> 24) & 0xFF;
                printf("Anomaly ip: %d.%d.%d.%d.\n",  bytes[0], bytes[1], bytes[2], bytes[3]);
//                std::string buffAsStdStr = buff;
//
//                logs.push(buffAsStdStr);
            }
            print_ip_info(conf.data_f, next_key, value);
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
            sum_count_ports += value;
            fprintf(conf.data_f, "\t%d count: %d\n", next_key, value);
            key = next_key;
        }

        newStats.unique_ips = unique_ips;
        if (unique_ips >= 100){
            newStats.unique_ips = (int) estimate;
        }
        newStats.unique_ports = unique_ports;
        newStats.average_count_per_ip = (int) ((double) sum_count_ips) / ((double) unique_ips);
        avg_count_per_ip += newStats.average_count_per_ip;
        count_per_ip_q.push(newStats.average_count_per_ip);
        avg_count_per_ip -= count_per_ip_q.front();
        count_per_ip_q.pop();

        if (newStats.unique_ips > (comparisonMultiplier * (avg_unique_ips / k_neighbors))){
//            logs.push("Anomaly of number of unique source IPs.");
            printf("Anomaly of number of unique source IPs.\n");
        }
        avg_unique_ips += newStats.unique_ips;
        unique_ips_q.push(newStats.unique_ips);
        avg_unique_ips -= unique_ips_q.front();
        unique_ips_q.pop();

        if (newStats.unique_ports > (comparisonMultiplier * (avg_unique_ports / k_neighbors))){
//            logs.push("Anomaly of number of unique destination PORTs.");
            printf("Anomaly of number of unique destination PORTs.\n");
        }
        avg_unique_ports += newStats.unique_ports;
        unique_ports_q.push(newStats.unique_ports);
        avg_unique_ports -= unique_ports_q.front();
        unique_ports_q.pop();

        provide_general_stats(newStats);
//        while (!logs.empty()){
//            printf("%s\n", logs.front());
//            logs.pop();
//        }

//        printf("Estimate of unique IP addresses during run time: %f\n", estimate);
//        fprintf(conf.data_f, "Estimate of unique IP addresses during run time: %f\n", estimate);

        sleep(SLEEP_SECONDS);
    }

    return 0;
}


int main(int argc, char **argv) {
    char *data_file = "net.dat";
    int chart_server_port = 8080;
    char *chart_server_port_char = NULL;
    char *ifindex_char = NULL;
    int c, err;
    conf.socket_data_provider = false;

    while ((c = getopt(argc, argv, "hi:f:d:s:p:")) != -1){
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
            case 'd':
                conf.socket_data_provider = true;
                break;
            case 's':
                conf.server_ip = std::string(optarg);
                break;
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



    // Opening data file
    conf.data_f = fopen(data_file, "a");
    if (!conf.data_f){
        fprintf(stderr, "ERROR: Unable to open file: %s.\n", data_file);
        return -2;
    }

    err = bpf_init();
    if (err != 0){
        fprintf(stderr, "ERROR: Failed to init BPF: %d.\n", err);
        return -3;
    }

    if (conf.socket_data_provider){
        err = socket_data_provider_init();
        if (err != 0){
            fprintf(stderr, "ERROR: Failed to init data provider server: %d.\n", err);
            return -3;
        }
    }

    signal(SIGINT, terminate);

    collect_info();

    printf("Program is terminated\n");

    fclose(conf.data_f);

    close(conf.bpf_prog_fd);

    if (conf.socket_data_provider){
        close(conf.sockfd);
    }

    return 0;
}
