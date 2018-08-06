#include <pcap.h>
#include <stdio.h>
#include <stdint.h>

void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
uint16_t my_ntohs(uint16_t n) {// n = 0x3412
	uint16_t temp1 = n & 0xFF00;// temp1 = 0x3400
	uint16_t temp2 = n & 0x00FF;// temp2 = 0x0012
	uint16_t result = temp1>>8 | temp2<<8;
	return result;
}
uint32_t myntohl(uint32_t n) {// n = 0x78563412
	uint32_t temp1 = n & 0xFF000000; // temp1 = 0x78000000 
	uint32_t temp2 = n & 0x00FF0000; // temp2 = 0x00560000
	uint32_t temp3 = n & 0x0000FF00; // temp3 = 0x00003400
	uint32_t temp4 = n & 0x000000FF; // temp4 = 0x00000012
	temp1 >>= 24;
	temp2 >>= 8;
	temp3 <<= 8;
	temp4 <<= 24;
	uint32_t result = temp1 | temp2 | temp3 | temp4;
	return result;
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
 
    u_char e_smac[6];
    u_char e_dmac[6];
    u_char ip_s[4];
    u_char ip_d[4];
    u_char e_type[2];
    u_char protocol[1];
    u_char tcp_s[2];
    u_char tcp_d[2];
    u_char data[16];
    for(int i= 0; i<=5;i++){//input e_smac  
    e_smac[i]= *(packet + i);
    }
    for(int i= 0; i<=5; i++){//input d_mac
    e_dmac[i]= *(packet + (i+6));
    }
    for(int i=0; i<=1; i++){//input ether type
    e_type[i] = *(packet + (i+12));
    } 
    printf("%u bytes captured\n", header->caplen);
    printf("eth.smac : ");
    for(int i=0; i<=5; i ++){//print e_smac
    printf("%02x.", e_smac[i]);
}
    printf("\n");
    printf("eth.dmac: ");
    for(int i=0; i<=5; i++){//print e_dmac
    printf("%02x.", e_dmac[i]);
}
if(e_type[0] == 0x08 && e_type[1] == 0x00){//ip check
for(int i=0; i<=3; i++){//input ip_s
      ip_s[i] = *(packet + (i+26));
  }
      for(int i=0; i<=3; i++){//input ip_d
      ip_d[i] = *(packet + (i+30));
  }
      protocol[0] = *(packet +23);//input protocol
      for(int i=0; i<=1; i++){//input tcp_s
      tcp_s[i] = *(packet + (i+34));
  }
      for(int i=0; i<=1; i++){//input tcp_d
      tcp_d[i] = *(packet + (i+36));
  }
        uint8_t tcpd[] = { tcp_d[0], tcp_d[1] };
	uint16_t* p1 = (uint16_t*)tcpd;
	uint16_t tcpDport = *p1;
        uint8_t tcps[] = { tcp_s[0], tcp_s[1] };
	uint16_t* p2 = (uint16_t*)tcps;
	uint16_t tcpSport = *p2;
	tcpDport = my_ntohs(tcpDport);
        tcpSport = my_ntohs(tcpSport);


      for(int i=0; i<=15; i++){
      data[i] = *(packet + (i+42));
  }


    printf("\n");
    printf("it is IPv4\n");
    printf("ip_s : ");    
    for(int i=0; i<=3;i++){//print ip_s
    printf("%03d.", ip_s[i]);
}
    printf("\n");
    printf("ip_d: ");
    for(int i=0; i<=3;i++){//print ip_d
    printf("%03d.", ip_d[i]);
}
if(protocol[0] == 0x06){// tcp udp check
    printf("\n");
    printf("this is tcp\n");
    printf("tcp_s: ");
    for(int i=0; i<=1; i++){//print tcp_s
    printf("%d", tcp_s[i]);
}
    printf("sprot : %d",tcpSport);
    printf("\n");
    printf("tcp_d: ");
    for(int i=0; i<=1; i++){//print tcp_d
    printf("%d", tcp_d[i]);
}
    printf("dport : %d",tcpDport);
    printf("\n");
    printf("data : ");
    for(int i=0; i<=15; i++){//print data
    printf("%x", data[i]);
}
}// if tcp
if(protocol[0] == 0x11){
printf("\n");
printf("this is udp\n");
    printf("udp_s: ");
    for(int i=0; i<=1; i++){//print tcp_s
    printf("%d", tcp_s[i]);
}
    printf("\n");
    printf("udp_d: ");
   // for(int i=0; i<=1; i++){//print tcp_d
   // printf("%d", tcp_d[i]);
    printf("%d",tcpDport);

    printf("\n");
    printf("data : ");
    for(int i=0; i<=15; i++){//print data
    printf("%x", data[i]);
}

}// if udp
}// if ip
if(e_type[0] == 0x08 && e_type[1] == 0x06){//arp
    u_char senderMac[6];
    u_char targetMac[6];
    u_char senderIp[4];
    u_char targetIp[4];
for(int i=0; i<=5; i++){//input senderMac
      senderMac[i] = *(packet + (i+22));
  }
      for(int i=0; i<=3; i++){//input senderIp
      senderIp[i] = *(packet + (i+28));
  }
      protocol[0] = *(packet +16);//input protocol
      for(int i=0; i<=5; i++){//input targetMac
      tcp_s[i] = *(packet + (i+32));
  }
      for(int i=0; i<=3; i++){//input targetIp
      tcp_d[i] = *(packet + (i+38));
  }
      for(int i=0; i<=15; i++){
      data[i] = *(packet + (i+42));
  }


    printf("\n");
    printf("it is arp\n");
    printf("senderMac : ");
    for(int i=0; i<=5;i++){//print senderMac
    printf("%02x.", senderMac[i]);
}
    printf("\n");
    printf("sdender ip: ");
    for(int i=0; i<=3;i++){//print senderIp
    printf("%03d.", senderIp[i]);
}
printf("\n");
     printf("it is arp\n");
     printf("senderMac : ");
     for(int i=0; i<=5;i++){//print targetMac
     printf("%02x.", targetMac[i]);
 }
     printf("\n");
     printf("sdender ip: ");
     for(int i=0; i<=3;i++){//print targetIp
     printf("%03d.", targetIp[i]);
 }

}

    printf("\n");
    printf("etype : ");
    for(int i=0; i<=1; i++){
    printf("e,%i : %02x",i, e_type[i]);
    }
    printf("\n");
    printf("pro : ");
    printf("%02x",protocol[0]);

    printf("\n");

  
}
pcap_close(handle);
  return 0;

}
