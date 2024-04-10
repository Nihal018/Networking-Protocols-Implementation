#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <arpa/inet.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>
#include <bits/ioctls.h>
#include <linux/if_arp.h>
#include <errno.h>
#include <pthread.h>

struct sockaddr_ll *L2_sock_addr = NULL, *L2_sock_dest = NULL;
struct ifreq ifr = {0};
int raw_socket;
socklen_t length, numbytes, tot_len;
unsigned short hardware_type = 0x1;
unsigned char buffer[128] = {0};
unsigned char recvbuffer[1024] = {0};
unsigned char ipaddr[4],ipaddr1[4];
char *interface_name = "enp0s3"; // Interface
struct arphdr *ARP_hdr;
struct ethhdr *eth_hdr;
struct ARP_source_dest *arp_source_dest;
int ifindex;
int rec = 0;

// Interrupt_handler – CTRL + C
void interrupt_handler (int signum) {
    close(raw_socket);
    free(L2_sock_addr);
    exit(0);
}

// print the packet 
void dumpmsg(unsigned char *recvbuffer, int length) {
    printf("Packet contains : ");
    for (int i = 0; i < length; i++) {
        printf("%02x ", recvbuffer[i]);
    }
    printf("\n");
}

// from header if_arp.h for ethernet 
struct ARP_source_dest {
    unsigned char ar_sha[ETH_ALEN]; // sender hardware address 
    unsigned char ar_sip[4]; // sender IP address 
    unsigned char ar_tha[ETH_ALEN]; // target hardware address 
    unsigned char ar_tip[4]; // target IP address 
};

void *ARP_Reply(){
    socklen_t leng = sizeof(struct sockaddr_ll);
    while(1){
        numbytes = recvfrom(raw_socket, buffer, tot_len, 
                    0,(struct sockaddr *)L2_sock_addr, &leng);
        if (numbytes == -1) {
            perror("Recvfrom : ");
        }
        if (ARP_hdr->ar_op != htons(ARPOP_REPLY)){continue;}
        if (arp_source_dest->ar_sip[0] != ipaddr1[0]){continue;}
        if (arp_source_dest->ar_sip[1] != ipaddr1[1]){continue;}
        if (arp_source_dest->ar_sip[2] != ipaddr1[2]){continue;}
        if (arp_source_dest->ar_sip[3] != ipaddr1[3]){continue;}
        rec = 1;
        printf("MACAddress : %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        eth_hdr->h_source[0],eth_hdr->h_source[1],
                        eth_hdr->h_source[2], eth_hdr->h_source[3],
                        eth_hdr->h_source[4], eth_hdr->h_source[5]);
        printf("IP address: %u.%u.%u.%u\n", arp_source_dest->ar_sip[0],
                                            arp_source_dest->ar_sip[1],
                                            arp_source_dest->ar_sip[2],
                                            arp_source_dest->ar_sip[3]);
        dumpmsg((unsigned char *)buffer, tot_len);
        break;
        
    }
}

int main (int argc,char *argv[]) {
    if (argc != 2){
        printf("Usage : %s <Target IP Address>\n",argv[0]);
        exit(0);
    }

    signal (SIGINT, interrupt_handler);

    if ((raw_socket = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP))) < 0) {
        perror("Socket : ");
        exit(0);
    }

    L2_sock_addr = (struct sockaddr_ll *)malloc(sizeof(struct sockaddr_ll));
    if (L2_sock_addr == NULL) {
        perror("Malloc : ");
        exit(1);
    }
    

    strncpy(ifr.ifr_name, interface_name, strlen(interface_name));

    // get the index number of the current interface
    if (ioctl(raw_socket, SIOCGIFINDEX, &ifr) < 0) {
        perror("IOCTL(index number) : ");
        exit(1);
    }
    ifindex = ifr.ifr_ifindex;

    // Get the HW MACADDRESS of the interface 
    if (ioctl(raw_socket, SIOCGIFHWADDR, &ifr) < 0) {
        perror("IOCTL(MAC address) : ");
        exit(1);
    }

    // Fill the socket destination to send to 
    L2_sock_addr->sll_family = AF_PACKET;
    L2_sock_addr->sll_ifindex = ifindex;
    L2_sock_addr->sll_protocol = htons(ETH_P_ARP);
    L2_sock_addr->sll_hatype = htons(ARPHRD_ETHER);
    L2_sock_addr->sll_pkttype = (PACKET_BROADCAST);
    L2_sock_addr->sll_halen = ETH_ALEN;
    L2_sock_addr->sll_addr[6] = 0x00;
    L2_sock_addr->sll_addr[7] = 0x00;

    // Ethernet header
    eth_hdr = (struct ethhdr *)buffer;

    for (int i = 0; i < ETH_ALEN; i++) {
        eth_hdr->h_source[i] = ifr.ifr_hwaddr.sa_data[i];
        L2_sock_addr->sll_addr[i] = ifr.ifr_hwaddr.sa_data[i];
    }
    printf("MACAddress : %02x:%02x:%02x:%02x:%02x:%02x\n", 
                            eth_hdr->h_source[0],eth_hdr->h_source[1],
                            eth_hdr->h_source[2], eth_hdr->h_source[3],
                            eth_hdr->h_source[4], eth_hdr->h_source[5]);

    eth_hdr->h_dest[0] = 0xff;
    eth_hdr->h_dest[1] = 0xff;
    eth_hdr->h_dest[2] = 0xff;
    eth_hdr->h_dest[3] = 0xff;
    eth_hdr->h_dest[4] = 0xff;
    eth_hdr->h_dest[5] = 0xff;

    eth_hdr->h_proto = htons(ETH_P_ARP);  // frame type

    // ARP packet header
    ARP_hdr = (struct arphdr *) (buffer + sizeof(struct ethhdr));
    ARP_hdr->ar_hrd = htons(hardware_type);     // Ethernet 
    ARP_hdr->ar_pro = htons(ETH_P_IP);          // IP 
    ARP_hdr->ar_hln = ETH_ALEN;                 // len(MAC)
    ARP_hdr->ar_pln = 4;                        // len(ipv4)
    ARP_hdr->ar_op = htons(ARPOP_REQUEST);      // ARP Request

    // Sender HW address
    arp_source_dest = (struct ARP_source_dest *) (buffer + sizeof(struct ethhdr) + sizeof(struct arphdr));
    arp_source_dest->ar_sha[0] = eth_hdr->h_source[0]; 
    arp_source_dest->ar_sha[1] = eth_hdr->h_source[1];
    arp_source_dest->ar_sha[2] = eth_hdr->h_source[2];
    arp_source_dest->ar_sha[3] = eth_hdr->h_source[3];
    arp_source_dest->ar_sha[4] = eth_hdr->h_source[4];
    arp_source_dest->ar_sha[5] = eth_hdr->h_source[5];

    // IP address of sender
    strncpy(ifr.ifr_name, interface_name, IFNAMSIZ - 1);
    if (ioctl(raw_socket, SIOCGIFADDR, &ifr) == -1) {
        perror("ioctl");
        exit(EXIT_FAILURE);
    }
    struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_addr;
    memcpy(ipaddr, &addr->sin_addr.s_addr, sizeof(ipaddr));

    // Print the IP address
    printf("IP address: %u.%u.%u.%u\n", ipaddr[0], ipaddr[1], ipaddr[2], ipaddr[3]);
    arp_source_dest->ar_sip[0] = ipaddr[0];
    arp_source_dest->ar_sip[1] = ipaddr[1];
    arp_source_dest->ar_sip[2] = ipaddr[2];
    arp_source_dest->ar_sip[3] = ipaddr[3];

    // Destination IP address
    char* ip = strtok(argv[1],".");
    ipaddr1[0] = atoi(ip);
    arp_source_dest->ar_tip[0] = atoi(ip);
    ip = strtok(NULL,".");
    ipaddr1[1] = atoi(ip);
    arp_source_dest->ar_tip[1] = atoi(ip);
    ip = strtok(NULL,".");
    ipaddr1[2] = atoi(ip);
    arp_source_dest->ar_tip[2] = atoi(ip);
    ip = strtok(NULL,".");
    ipaddr1[3] = atoi(ip);
    arp_source_dest->ar_tip[3] = atoi(ip);

    // Final Packet
    tot_len = (sizeof(struct ethhdr) + sizeof(struct arphdr) + sizeof(struct ARP_source_dest));
    dumpmsg((unsigned char *)buffer, tot_len);
    numbytes = sendto(raw_socket, buffer, tot_len,                                             
                    0,(struct sockaddr *)L2_sock_addr, sizeof(struct sockaddr_ll));            // ethernet frame
    if (numbytes == -1) {
        perror("Sendto : ");
    }
    pthread_t recv;
    pthread_create(&recv,NULL,ARP_Reply,NULL);
    int l = 0;
    while (l < 20){
        l++;
        if(rec){break;}
        sleep(1);
    }
    if(rec == 0){
        pthread_cancel(recv);
        printf("No response received no device might have the given IP\n");
    }
    free(L2_sock_addr);
    close(raw_socket);
    return 0;
}

