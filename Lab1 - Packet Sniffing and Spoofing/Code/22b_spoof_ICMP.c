#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include "myheader.c"


unsigned short in_cksum (unsigned short *buf, int length)
{

	unsigned short *w = buf;
   int nleft = length;
   int sum = 0;
   unsigned short temp=0;

   while (nleft > 1)  {
       sum += *w++;
       nleft -= 2;
   }

     if (nleft == 1) {
        *(u_char *)(&temp) = *(u_char *)w ;
        sum += temp;
   }

   sum = (sum >> 16) + (sum & 0xffff);  // add hi 16 to low 16 
   sum += (sum >> 16);                  // add carry 
   return (unsigned short)(~sum);

}


void send_raw_ip_packet(struct ipheader* ip)
{
	struct sockaddr_in dest_info;
	int enable = 1;
	//Step1: Create a raw network socket
	int sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

	//Step2: Set Socket option
	setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &enable, sizeof(enable));

	//Step3: Provide destination information
	dest_info.sin_family = AF_INET;
	dest_info.sin_addr = ip->iph_destip;

	//Step4: Send the packet out
	sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}

void main() {

	char buffer[1500];
	memset(buffer, 0, 1500);

	/***** Preparing the ICMP Header *****/
	struct icmpheader *icmp = (struct icmpheader *) (buffer + sizeof(struct ipheader));
	icmp->icmp_type = 8; //8 is for  request and 0 is for reply
	icmp->icmp_chksum = 0;
	icmp->icmp_chksum = in_cksum((unsigned short *)icmp, sizeof(struct icmpheader));


	/***** Preparing the IP Header *****/
	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver=4;
	ip->iph_ihl=5;
	ip->iph_ttl=20;
	ip->iph_sourceip.s_addr = inet_addr("10.0.2.4");
	ip->iph_destip.s_addr = inet_addr("10.0.2.3");
	ip->iph_protocol = IPPROTO_UDP;
	ip->iph_len=htons(sizeof(struct ipheader) + sizeof(struct udpheader));

	send_raw_ip_packet(ip);

}
