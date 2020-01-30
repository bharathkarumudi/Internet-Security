#include <pcap.h>
#include <stdio.h>

void got_packet(u_char *args, const struct pcap_pkthdr *header,const u_char *packet)
{
 printf("Got a packet \n");
}


int main()
{

 pcap_t *handle;
 char errbuf[PCAP_ERRBUF_SIZE];
 struct bpf_program fp;
 char filter_exp[] = "ip proto icmp";
 bpf_u_int32 net;

 handle = pcap_open_live("enp0s3", BUFSIZ,1,1000,errbuf);

 pcap_compile(handle, &fp, filter_exp, 0, net);
 pcap_setfilter(handle, &fp);

 pcap_loop(handle, -1, got_packet, NULL);

 pcap_close(handle);
 return 0;
}

