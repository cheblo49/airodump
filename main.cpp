#include <iostream>
#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include "radiotap.h"
#include "dot11.h"
#include <vector>
#include <map>
#include <set>

void usage() {
    printf("syntax: airodump <interface>\n");
    printf("sample: airodump wlan0\n");
}

int main(int argc, char* argv[]){

    if (argc != 2) {
      usage();
      return -1;
    }

    int count = 0 ;

    char* dev = argv[1]; // dev = wlan0
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); // packet capture

    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    printf("    BSSID               PWR  Beacons    #Data, #/s  CH   MB   ENC CIPHER  AUTH ESSID  \n"); // print

    set<vector<uint8_t>> ap_list ;
    map<vector<uint8_t>,struct ap> ap_ls;

    while(true){

        if(count == 50)
            break;

        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle,&header,&packet); // get packet

        if(res ==0)
            continue;
        if(res == -1 || res == -2)
            break;

        struct radiotap *rd = (struct radiotap *) packet;
        struct dot11_header *dot11 = (struct dot11_header *)(packet+rd->h_len);
        //struct dot11_header *dot11;
        //dot11 = (struct dot11_header*)(rd + sizeof(struct radiotap));


        if( dot11->fc.type != 0 || dot11->fc.subtype!= 0x08) // dot11->fc.tpye != 0 ||
            continue;

        uint8_t *target = dot11->bssid;

        vector<uint8_t> temp;
        vector<uint8_t> name;


        for(int i = 0 ; i < 6 ; i++) // bssid -> target -> temp
            temp.push_back(*(target+i));

        count++;

        if(!ap_list.insert(temp).second){
            ap_ls.find(temp)->second.beacon++; continue;
        }

        struct taged_parm *size_ptr1= (struct taged_parm *)(packet+rd->h_len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed));
        uint8_t size1 = size_ptr1->tag_len;

        for(int i=0;i<size1;i++){
            name.push_back(*((uint8_t *)(packet+rd->h_len+sizeof(dot11_header)+sizeof(struct beacon_fixed)+2+i)));
        }

        uint8_t temp_type;

        int cot = 0;
        int j = 1;

        while(cot != 10){

            struct taged_parm *size_ptr2= (struct taged_parm *)(packet+rd->h_len+sizeof(struct dot11_header)+sizeof(struct beacon_fixed)+(2*j)+size1);

            printf("\ntemp_type : %x\n", size_ptr2->tag_num);
            printf("\nlen: %x", size_ptr2->tag_len);

            temp_type = size_ptr2->tag_num;
            size1 = size1 +size_ptr2->tag_len;

            if(temp_type == 0x30)
                printf("\nGOOOOOOOOOOOOOOOOOOD!!!\n");
            j++;
            cot ++;
       }

        printf("\nssid size1 = %d\n", size1);
       // printf("\nssid size2 = %d\n", size2);

        struct ap temp_ap;
        temp_ap.beacon=1; // start beacon
        temp_ap.essid=name; // sside_name
        temp_ap.pwr=-((~(*((uint8_t*)rd+22))+1)&0x000000FF); // size
        temp_ap.essid_len=size1; // ssid_size

        if((rd->channel-2412)/5 == 0) // channel
            temp_ap.chan = 1;
        else
            temp_ap.chan = ((rd->channel-2412)/5)+ 1;

        ap_ls.insert({temp,temp_ap});

    }
    int num=1;

    for(auto i=ap_ls.begin();i!=ap_ls.end();i++){
        printf("[%d] ",num++);

        for(int j=0;j<5;j++)
            printf("%02x:",i->first[j]);

        printf("%02x",i->first[5]);
        printf("   %3d",i->second.pwr);
        printf("  %7d",i->second.beacon);
        printf("           %7d",i->second.chan);
        printf("                         ");

        for(auto k=i->second.essid.begin();k<i->second.essid.end();k++)
            printf("%c",(*k));
        printf("\n");
    }

    printf("total AP : %ld\n",ap_list.size());
}
