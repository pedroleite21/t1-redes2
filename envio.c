#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include "checksum/checksum.h";

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define ETHERTYPE 0x0806
#define REPLY 0X0002

struct udp_header
{
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t udp_len;
	uint16_t udp_chksum;
};

struct app
{
	uint16_t id;
	uint8_t control;
	uint8_t padd;
	uint8_t data[512];
	uint16_t app_checksum;
};

int main(int argc, char *argv[])
{
	int fd;
	struct ifreq if_idx;
	struct ifreq if_mac;
	struct sockaddr_ll socket_address;
	char ifname[IFNAMSIZ];
	int frame_len = 0;
	char buffer[BUFFER_SIZE];
	char data[MAX_DATA_SIZE];
	char dest_mac[] = {0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF}; //broadcast
	short int ethertype = htons(0x0806);

	short int hardtype = htons(0x0001);
	short int proptype = htons(0x0800);

	char hardsize = 0x06;
	char propsize = 0x04;

	short int operation = htons(0x0001);

	char orig_ip[] = {192, 168, 1, 187};

	char dest_ip[] = {192, 168, 1, 187};

	short int source_port = htons(54323);
	short int dest_port = htons(54321);
	short int length = htons(sizeof(struct udp_header));
	short int checksum = 0;

	if (argc != 2)
	{
		printf("Usage: %s iface\n", argv[0]);
		return 1;
	}
	strcpy(ifname, argv[1]);

	/* Cria um descritor de socket do tipo RAW */
	if ((fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		perror("socket");
		exit(1);
	}

	/* Obtem o indice da interface de rede */
	memset(&if_idx, 0, sizeof(struct ifreq));
	strncpy(if_idx.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFINDEX, &if_idx) < 0)
	{
		perror("SIOCGIFINDEX");
		exit(1);
	}

	/* Obtem o endereco MAC da interface local */
	memset(&if_mac, 0, sizeof(struct ifreq));
	strncpy(if_mac.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &if_mac) < 0)
	{
		perror("SIOCGIFHWADDR");
		exit(1);
	}

	/* Indice da interface de rede */
	socket_address.sll_ifindex = if_idx.ifr_ifindex;

	/* Tamanho do endereco (ETH_ALEN = 6) */
	socket_address.sll_halen = ETH_ALEN;

	/* Endereco MAC de destino */
	memcpy(socket_address.sll_addr, dest_mac, MAC_ADDR_LEN);

	/* Preenche o buffer com 0s */
	memset(buffer, 0, BUFFER_SIZE);

	/* Monta o cabecalho Ethernet */

	/* Preenche o campo de endereco MAC de destino */
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo de endereco MAC de origem */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* Preenche o campo EtherType */
	memcpy(buffer + frame_len, &ethertype, sizeof(ethertype));
	frame_len += sizeof(ethertype);

	/* */
	memcpy(buffer + frame_len, 0x45, 4);
	frame_len += 4;

	memcpy(buffer + frame_len, 0x00, 4);
	frame_len += 4;

	memcpy(buffer + frame_len, htons(512), 16);
	frame_len += 16;
	
	memcpy(buffer + frame_len, htons(0x00), 16);
	frame_len += 16;

	memcpy(buffer + frame_len, htons(0x00), 16);
	frame_len += 16;

	memcpy(buffer + frame_len, 50, 8);
	frame_len += 8;

	memcpy(buffer + frame_len, 17, 8);
	frame_len += 8;

	memcpy(buffer + frame_len, htons(0x0000), 16);
	frame_len += 16;

	/* sender Ethernet addr */
	memcpy(buffer + frame_len, if_mac.ifr_hwaddr.sa_data, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	/* sender IP addr */
	memcpy(buffer + frame_len, orig_ip, sizeof(orig_ip));
	frame_len += sizeof(orig_ip);

	/* target Ethernet addr */
	memcpy(buffer, dest_mac, MAC_ADDR_LEN);
	frame_len += MAC_ADDR_LEN;

	dest_ip[0] = orig_ip[0];
	dest_ip[1] = orig_ip[1];
	dest_ip[2] = orig_ip[2];
	dest_ip[3] = orig_ip[3];

	memcpy(buffer + frame_len, dest_ip, sizeof(dest_ip));
	frame_len += sizeof(dest_ip);

	/* ip checksum */
	memcpy(buffer+frame_len, htons((~ipchksum((uint8_t *)&buffer_u.cooked_data.payload.ip) & 0xffff)), 16);
	frame_len += 16;

	/* UDP header */
	memcpy(buffer + frame_len, &source_port, sizeof(source_port));
	frame_len += sizeof(source_port);

	memcpy(buffer + frame_len, &dest_port, sizeof(dest_port));
	frame_len += sizeof(dest_port);

	memcpy(buffer + frame_len, &length, sizeof(length));
	frame_len += sizeof(length);

	memcpy(buffer + frame_len, &checksum, sizeof(checksum));
	frame_len += sizeof(checksum);

	if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
	{
		perror("send");
		close(fd);
		exit(1);
	}

	printf("Pacotes enviados.\n");
	printf("Esperando replys...\n\n");
	unsigned char *reply;

	while (1)
	{
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		unsigned char ip_src[4];
		unsigned char ip_dst[4];
		short int ethertype;
		short int oprecieve;

		/* Recebe pacotes */
		if (recv(fd, (char *)&buffer, BUFFER_SIZE, 0) < 0)
		{
			perror("recv");
			close(fd);
			exit(1);
		}

		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer + sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer + sizeof(mac_dst) + sizeof(mac_src), sizeof(ethertype));
		ethertype = ntohs(ethertype);
		reply = (buffer + sizeof(mac_dst) + sizeof(mac_src) + sizeof(ethertype));

		memcpy(&oprecieve, reply + 6, sizeof(oprecieve));
		oprecieve = ntohs(oprecieve);

		memcpy(ip_src, reply + 14, sizeof(ip_src));

		memcpy(ip_dst, reply + 24, sizeof(ip_dst));
		if (ethertype == ETHERTYPE && oprecieve == 2 && (orig_ip[0] == ip_dst[0] && orig_ip[1] == ip_dst[1] && orig_ip[2] == ip_dst[2] && orig_ip[3] == ip_dst[3]))
		{
			printf("IP: %d.%d.%d.%d\t", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n",
				   mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("\n");
		}
	}

	close(fd);
	return 0;
}
