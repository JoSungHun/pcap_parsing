#include <pcap.h>
#include <stdio.h>

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
 
    u_char e_smac[6];
    u_char e_dmac[6];
    u_char ip_s[4];
    u_char ip_d[4];
    u_char tcp_s[2];
    u_char tcp_d[2];
    u_char data[16];
    for(int i= 0; i<=5;i++){//input e_smac  
    e_smac[i]= *(packet + i);
    }
    for(int i= 0; i<=5; i++){//input d_mac
    e_dmac[i]= *(packet + (i+6));
    }
    for(int i=0; i<=3; i++){//input ip_s
    ip_s[i] = *(packet + (i+26));
}
    for(int i=0; i<=3; i++){//input ip_d
    ip_d[i] = *(packet + (i+30));
}
    for(int i=0; i<=1; i++){//input tcp_s
    tcp_s[i] = *(packet + (i+34));
}
    for(int i=0; i<=1; i++){//input tcp_d
    tcp_d[i] = *(packet + (i+36));
}
    for(int i=0; i<=15; i++){
    data[i] = *(packet + (i+42));
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
    printf("\n");
    printf("ip_s : ");    
    for(int i=0; i<=3;i++){//print ip_s
    printf("%03d.", ip_s[i]);
}
    printf("\n");
    printf("ip_d: ");
    for(int i=0; i<=3;i++){//print ip_d
    printf("%03d.", ip_d[i]);
}
    printf("\n");
    printf("tcp_s: ");
    for(int i=0; i<=1; i++){//print tcp_s
    printf("%d", tcp_s[i]);
}
    printf("\n");
    printf("tcp_d: ");
    for(int i=0; i<=1; i++){//print tcp_d
    printf("%d", tcp_d[i]);
}
    printf("\n");
    printf("data : ");
    for(int i=0; i<=15; i++){//print data
    printf("%x", data[i]);
}
    printf("\n");
     
  }

  pcap_close(handle);
  return 0;
}
