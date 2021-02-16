#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <net/ethernet.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <pcap.h>

void packet_handler(u_char *param,
  const struct pcap_pkthdr *header, const u_char *pkt_data) {
  printf("caplen : %d\n", header->caplen);
  printf("len : %d\n", header->len);
}

uint16_t my_ntohs(const u_char* num) {
   // int _num = *num;
    uint16_t _num = *(const uint16_t*)num;
    return _num << 8 | _num >> 8;
}

void printHexValue(const char* msg, const u_char* start, int32_t size, const char delim){
  printf("%s", msg);
  for(int i = 0; i < size-1; i++)
    printf("%02x%c", start[i], delim);
  printf("%02x\n", start[size-1]);
}

int main(int argc, char **argv) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *devices;
    pcap_if_t *d; 
    struct pcap_addr *a;
    int devCnt = 0;
    
    pcap_t *inHandle; 
    pcap_t *outHandle; 


    if (pcap_findalldevs(&devices, errbuf) < 0) {
        printf("pcap_findalldevs error\n");
        return 1;
    }
    for (d=devices; d; d=d->next) {
        printf("%d :  %s\n", ++devCnt, (d->description)?(d->description):(d->name));
    }

    int inputNo = -1;  
    int outputNo = -1; 

    printf("input dev interface number : "); 
    scanf("%d", &inputNo); 
    if (!(inputNo > 0 && inputNo <= devCnt)) {
        printf("wrong input dev number\n");
        return 1;
    }
    inputNo--; 

    printf("output dev interface number : "); 
    scanf("%d", &outputNo); 
    if (!(outputNo > 0 && outputNo <= devCnt)) {
        printf("number error\n");
        return 1;
    }
    outputNo--; 

    int idx = 0; 
    for( d = devices, idx = 0; d; d = d->next){
        if( idx == inputNo ){
            if(!(inHandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf))){
                printf("fail to open inut devices %s\n", d->name);
                pcap_freealldevs(devices); 
                exit(-1);  
            }
            break; 
        }
        idx++; 
    } 

    for( d = devices, idx = 0; d; d = d->next){
        if( idx == inputNo ){
            if(!(outHandle = pcap_open_live(d->name, 65536, 1, 1000, errbuf))){
                printf("fail to open inut devices %s\n", d->name);
                pcap_freealldevs(devices); 
                exit(-1);  
            }
            break; 
        }
        idx++; 
    } 

    while(true){
        struct pcap_pkthdr* header; 
        const u_char* packet; 
        int res = pcap_next_ex(inHandle, &header, &packet); 
        if(res == 0)
            continue; 
        if(res == -1 || res == -2){
            printf("error in captureing...\n"); 
            break; 
        }
        else{
            uint16_t type = my_ntohs(packet+12); 
            if(type != 0x88a4)
                continue; 
            printHexValue("get from ", packet, 6, ':'); 
            if(pcap_inject(outHandle, packet, header->caplen) == header->caplen)
                printf("RELAY success\n!"); 
        }

    }
    pcap_freealldevs(devices); 
    pcap_close(inHandle); 
    pcap_close(outHandle); 

    return 0;
}