#include <pcap.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <iostream>

typedef struct EthernetHeader{
    unsigned char DesMac[6];
    unsigned char SrcMac[6];
    unsigned short Type;
}ETH;
typedef struct IPHeader{
    unsigned char Version : 4;
    unsigned char IHL : 4;
    unsigned char TOS;
    u_short TotalLen;
    unsigned short Identifi;
    unsigned char Flagsx : 1;
    unsigned char FlagsD : 1;
    unsigned char FlagsM : 1;
    unsigned int FO : 13;
    unsigned char TTL;
    unsigned char Protocal;
    unsigned short HeaderCheck;
    struct in_addr SrcAdd;
    struct in_addr DstAdd;
}IPH;
typedef struct TCPHeader{
    unsigned short SrcPort;
    unsigned short DstPort;
    unsigned int SN;
    unsigned int AN;
    unsigned char Offset : 4;
    unsigned char Reserved : 4;
    unsigned char FlagsC : 1;
    unsigned char FlagsE : 1;
    unsigned char FlagsU : 1;
    unsigned char FlagsA : 1;
    unsigned char FlagsP : 1;
    unsigned char FlagsR : 1;
    unsigned char FlagsS : 1;
    unsigned char FlagsF : 1;
    unsigned short Window;
    unsigned short Check;
    unsigned short UP;
}TCPH;
typedef struct HttpH
{
    uint16_t HTP[10];
}HttpH;

void Print_Eth(const u_char *data){
    ETH *eth = (ETH *)data;
    printf("\n===ETH\n");
    printf("DMac : %02x : %02x : %02x : %02x : %02x : %02x\n",eth->DesMac[0], eth->DesMac[1], eth->DesMac[2], eth->DesMac[3], eth->DesMac[4], eth->DesMac[5]);
    printf("SMac : %02x : %02x : %02x : %02x : %02x : %02x\n",eth->SrcMac[0], eth->SrcMac[1], eth->SrcMac[2], eth->SrcMac[3], eth->SrcMac[4], eth->SrcMac[5]);
}
void Print_IP(const u_char *data){
    IPH *iph = (IPH *)data;
    printf("\n===IP\n");
    printf("s_ip : %s\n", inet_ntoa(iph->SrcAdd));
    printf("d_ip : %s\n", inet_ntoa(iph->DstAdd));
}
void Print_TCP(const u_char *data){
    TCPH *tcph = (TCPH *)data;
    printf("\n===TCP\n");
    printf("s_prot : %d\n", ntohs(tcph->SrcPort));
    printf("d_port : %d\n", ntohs(tcph->DstPort));
}
void Print_Data(const u_char *data){
    HttpH *hh = (HttpH *)data;
    printf("\nData : ");
    for(int i = 0; i < 10; i++){
        printf("%02x : ",hh->HTP[i]);
    }
}
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
    printf("\n%u bytes captured\n", header->caplen);
    Print_Eth(packet);
    ETH *eth = (ETH *)packet;
        packet += 14;
        Print_IP(packet);

    IPH *iph = (IPH *)packet;

        packet += (iph->IHL*4);
        Print_TCP(packet);

    TCPH *tcph = (TCPH *)packet;
    packet += (tcph->Offset*4);
    Print_Data(packet);

  }

  pcap_close(handle);
  return 0;
}

