#include "wireview.h"
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_PACKETS 100

void packet_handler(u_char *user_data, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    // This function will be called for each packet captured
    // You can process the packet data here
    printf("Packet captured, length: %d\n", pkthdr->len);
}

int main(int argc, char *argv[])
{

    pcap_t *pcap_handle; //the session handle
    char errbuf[PCAP_ERRBUF_SIZE]; //error str
    const char *filename = "Project1/project2-dns.pcap"; //name of file
    pcap_handle = pcap_open_offline(filename, errbuf);
    if (pcap_handle == NULL) {
        fprintf(stderr, "Error opening packet capture file: %s\n", errbuf);
        return 1;
    }

    int link_type = pcap_datalink(pcap_handle);
    if (link_type == -1) {
        fprintf(stderr, "Error getting link type: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return 1;
    }

    // Print the link-layer header type
    printf("Link type: %s\n", pcap_datalink_val_to_name(link_type));
    if (pcap_loop(pcap_handle, MAX_PACKETS, packet_handler, NULL) == -1) {
        fprintf(stderr, "Error processing packets: %s\n", pcap_geterr(pcap_handle));
        pcap_close(pcap_handle);
        return 1;
    }



}