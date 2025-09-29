#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <pcap.h>

#define MAX_PROCESSED_PACKETS 1000

struct processed_packet {
    char src_ip[INET_ADDRSTRLEN];
    char dst_ip[INET_ADDRSTRLEN];
    int protocol;
    unsigned short src_port;
    unsigned short dst_port;
};

unsigned int hash_packet(struct processed_packet *pkt) {
    unsigned int hash = 0;
    hash = (hash * 31) + inet_addr(pkt->src_ip);
    hash = (hash * 31) + inet_addr(pkt->dst_ip);
    hash = (hash * 31) + pkt->protocol;
    hash = (hash * 31) + pkt->src_port;
    hash = (hash * 31) + pkt->dst_port;
    return hash;
}

int is_processed(struct processed_packet *pkt, unsigned int *processed_hashes, int processed_count) {
    unsigned int hash = hash_packet(pkt);
    for (int i = 0; i < processed_count; i++) {
        if (processed_hashes[i] == hash) {
            return 1;
        }
    }
    return 0;
}

void log_packet(struct processed_packet *pkt, const char *status) {
 printf("Src: %s, Dst: %s, Protocol: %d, Src Port: %d, Dst Port: %d %s\n",
           pkt->src_ip, pkt->dst_ip, pkt->protocol, pkt->src_port, pkt->dst_port, status);
}

void add_processed(struct processed_packet *pkt, unsigned int *processed_hashes, int *processed_count) {
    unsigned int hash = hash_packet(pkt);
    processed_hashes[*processed_count] = hash;
    (*processed_count)++;
}

void process_packet(struct pcap_pkthdr header, const u_char *packet, unsigned int *processed_hashes, int *processed_count) {
    struct processed_packet pkt;
    memset(&pkt, 0, sizeof(pkt));

    unsigned char *ip_header = (unsigned char *)(packet + 14);
    unsigned char *src_ip = ip_header + 12;
    unsigned char *dst_ip = ip_header + 16;

    snprintf(pkt.src_ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", src_ip[0], src_ip[1], src_ip[2], src_ip[3]);
    snprintf(pkt.dst_ip, INET_ADDRSTRLEN, "%d.%d.%d.%d", dst_ip[0], dst_ip[1], dst_ip[2], dst_ip[3]);

    pkt.protocol = ip_header[9];

    if (pkt.protocol == 6 || pkt.protocol == 17) {
        unsigned char *transport_header = ip_header + 20;
        pkt.src_port = (transport_header[0] << 8) | transport_header[1];
        pkt.dst_port = (transport_header[2] << 8) | transport_header[3];
    }

    if (is_processed(&pkt, processed_hashes, *processed_count)) return;

    if (strcmp(pkt.src_ip, "8.8.8.8") == 0 || pkt.src_port == 22 || pkt.dst_port == 22) {
        log_packet(&pkt, "Allowed:");
        add_processed(&pkt, processed_hashes, processed_count);
        return;
    }
if (
        strcmp(pkt.src_ip, "192.168.1.1") == 0 || strcmp(pkt.dst_ip, "192.168.1.1") == 0 ||
        strcmp(pkt.src_ip, "10.0.0.5") == 0 || strcmp(pkt.dst_ip, "172.16.0.10") == 0
    ) {
        log_packet(&pkt, " --> Packet is Blocked: IP Rule got Matched");
    } else if (
        pkt.src_port == 80 || pkt.dst_port == 80 ||
        pkt.src_port == 443 || pkt.dst_port == 21 ||
        (pkt.src_port >= 1000 && pkt.src_port <= 2000) ||
        (pkt.dst_port >= 1000 && pkt.dst_port <= 2000)
    ) {
        log_packet(&pkt, " --> Packet is Blocked: Port Rule got Matched");
    } else if (
        pkt.protocol == 6 || pkt.protocol == 17 || pkt.protocol == 1
    ) {
        log_packet(&pkt, " --> Packet is Blocked: Protocol Rule got Matched");
    } else {
        log_packet(&pkt, " --> Packet is Allowed");
    }

    add_processed(&pkt, processed_hashes, processed_count);
}

void packet_handler(unsigned char *user_data, const struct pcap_pkthdr *pkthdr, const unsigned char *packet) {
    unsigned int *processed_hashes = (unsigned int *)user_data;
    int *processed_count = (int *)(user_data + sizeof(unsigned int) * MAX_PROCESSED_PACKETS);
    process_packet(*pkthdr, packet, processed_hashes, processed_count);
}

int main() {
    pcap_t *handle;
    char errbuf[PCAP_ERRBUF_SIZE];
    unsigned int processed_hashes[MAX_PROCESSED_PACKETS] = {0};
    int processed_count = 0;

    handle = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        printf("Error opening pcap: %s\n", errbuf);
        return -1;
    }

    printf("Firewall is running... .\n");

    pcap_loop(handle, 0, packet_handler, (unsigned char *)processed_hashes);

    pcap_close(handle);
    return 0;
}  

