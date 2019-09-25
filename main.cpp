#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <algorithm>
using namespace std;

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    
    u_char dst_mac[6] = {packet[0], packet[1], packet[2], packet[3], packet[4], packet[5]};
    u_char src_mac[6] = {packet[6], packet[7], packet[8], packet[9], packet[10], packet[11]};
    uint16_t* pro = (uint16_t*)(packet + 12);
    uint16_t protocol = ntohs(*pro); // ethernet's upper layer protocol
    printf("\n");
    printf("src mac : %02x:%02x:%02x:%02x:%02x:%02x\n", src_mac[0], src_mac[1], src_mac[2], src_mac[3], src_mac[4], src_mac[5]);
    printf("dst mac : %02x:%02x:%02x:%02x:%02x:%02x\n", dst_mac[0], dst_mac[1], dst_mac[2], dst_mac[3], dst_mac[4], dst_mac[5]);
    int ethlen = 14;
    
     if (protocol != 0x0800) continue;
    char* tem1 = (char*)(packet + ethlen);
    int iplen = (*tem1 & 0x0f) * 4; // ip header's length
    uint8_t* ippro = (uint8_t*)(packet + ethlen + 9);
    uint8_t ipprotocol = (*ippro); // ip's upper layer protocol
    uint32_t* src_iptem = (uint32_t*)(packet + ethlen + 12);
    uint32_t src_ip = ntohl(*src_iptem);
    uint32_t* dst_iptem = (uint32_t*)(packet + ethlen + 16);
    uint32_t dst_ip = ntohl(*dst_iptem);
    printf("src ip : %d.%d.%d.%d\n", (src_ip>>24)&0xff, (src_ip>>16)&0xff, (src_ip>>8)&0xff, src_ip&0xff);
    printf("dst ip : %d.%d.%d.%d\n", (dst_ip>>24)&0xff, (dst_ip>>16)&0xff, (dst_ip>>8)&0xff, dst_ip&0xff);
    
    if (ipprotocol != 0x06) continue;
    uint16_t* src_porttem = (uint16_t*)(packet + ethlen + iplen);
    uint16_t src_port = ntohs(*src_porttem);
    uint16_t* dst_porttem = (uint16_t*)(packet + ethlen + iplen + 2);
    uint16_t dst_port = ntohs(*dst_porttem);
    char* tem2 = (char*)(packet + ethlen + iplen + 12);
    int tcplen = ((*tem2 & 0xf0) >> 4) * 4; // tcp header's length
    printf("src port : %d\n", src_port);
    printf("dst port : %d\n", dst_port);
    
    int datalen = header->caplen - ethlen - iplen - tcplen; // data's length
    if(datalen <= 6) continue; // too little data is also ignored(may be padding)
    u_char* data = (u_char*)(packet + ethlen + iplen + tcplen);
    printf("data : ");
    for(int i = 0; i < min(datalen,32); i++) // if data's length is smaller than 32bytes, print all the data
      printf("%02x", data[i]);
    printf("\n");
  }
  pcap_close(handle);
  return 0;
}
