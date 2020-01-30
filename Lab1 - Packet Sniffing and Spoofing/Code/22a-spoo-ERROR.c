#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

struct ipheader {
 unsigned char iph_ihl:4,
               iph_ver:4;

 unsigned char iph_tos;
 unsigned short int iph_len;
 unsigned short int iph_ident;
 unsigned short int iph_flag:3,
                    iph_offset:13;
 unsigned char iph_ttl;
 unsigned char iph_protocol;
 unsigned short int iph_chksum;
 struct in_addr iph_sourceip;
 struct in_addr iph_destip;

};

struct udpheader {
 u_int16_t udp_sport;
 u_int16_t udp_dport;
 u_int16_t udp_ulen;
 u_int16_t udp_sum;

};

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
	dest_info.sin_addr.saddr = ip->iph_destip;

	//Step4: Send the packet out
	sendto(sock, ip, ntohs(ip->iph_len),0, (struct sockaddr *)&dest_info, sizeof(dest_info));
	close(sock);
}

void main() {

	char buffer[1500];
	memset(buffer, 0, 1500);

	struct udpheader *udp = (struct udpheader *)(buffer + sizeof(struct ipheader));
	char *data = buffer + sizeof(struct ipheader) + sizeof(struct udpheader);
	char *msg = "Hello!!\n";
	int data_len = strlen(msg);
	memcpy(data, msg, data_len);

	udp->udp_sport=htons(9190);
	udp->udp_dport=htons(9090);
	udp->udp_ulen=htons(sizeof(struct udpheader) + data_len);
	udp->udp_sum=0;

	struct ipheader *ip = (struct ipheader *)buffer;
	ip->iph_ver=4;
	ip->iph_ihl=5;
	ip->iph_ttl=20;
	ip->iph_sourceip.s_addr = inet_addr("10.0.2.10");
	ip->iph_destip.s_addr = inet_addr("10.0.2.4");
	ip->iph_protocol = IPPROTO_UDP;
	ip->iph_len=htons(sizeof(struct ipheader) + sizeof(struct udpheader) + data_len);

	send_raw_ip_packet(ip);

}
