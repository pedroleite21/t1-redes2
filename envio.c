#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>

#define MAC_ADDR_LEN 6
#define BUFFER_SIZE 1600
#define MAX_DATA_SIZE 1500
#define ETHERTYPE 0x0806
#define REPLY 0X0002

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
	
	char dest_ip[] = {192, 168, 1, 48};

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

	/* Preenche o campo hard type */
	memcpy(buffer + frame_len, &hardtype, sizeof(hardtype));
	frame_len += sizeof(hardtype);

	/* prop type */
	memcpy(buffer + frame_len, &proptype, sizeof(proptype));
	frame_len += sizeof(proptype);

	/* hard size */
	memcpy(buffer + frame_len, &hardsize, sizeof(hardsize));
	frame_len += sizeof(hardsize);

	/* prop size */
	memcpy(buffer + frame_len, &propsize, sizeof(propsize));
	frame_len += sizeof(propsize);

	/* op */
	memcpy(buffer + frame_len, &operation, sizeof(operation));
	frame_len += sizeof(operation);

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
	// dest_ip[3] = orig_ip[3];

	int i = 0;
	for (i = 1; i < 255; i++) {

		if (i == orig_ip[3])
			continue;

		dest_ip[3] = i;

		memcpy(buffer + frame_len, dest_ip, sizeof(dest_ip));
		frame_len += sizeof(dest_ip);

		if (sendto(fd, buffer, frame_len, 0, (struct sockaddr *)&socket_address, sizeof(struct sockaddr_ll)) < 0)
		{
			perror("send");
			close(fd);
			exit(1);
		}

		frame_len -= sizeof(dest_ip);
	}

	printf("Pacotes enviados.\n");
	printf("Esperando replys...\n\n");
	unsigned char *reply;

	while(1) {
		unsigned char mac_dst[6];
		unsigned char mac_src[6];
		unsigned char ip_src[4];
		unsigned char ip_dst[4];
		short int ethertype;
		short int oprecieve;
		

		/* Recebe pacotes */
		if (recv(fd,(char *) &buffer, BUFFER_SIZE, 0) < 0) {
			perror("recv");
			close(fd);
			exit(1);
		}

		memcpy(mac_dst, buffer, sizeof(mac_dst));
		memcpy(mac_src, buffer+sizeof(mac_dst), sizeof(mac_src));
		memcpy(&ethertype, buffer+sizeof(mac_dst)+sizeof(mac_src), sizeof(ethertype));
		ethertype = ntohs(ethertype);
		reply = (buffer+sizeof(mac_dst)+sizeof(mac_src)+sizeof(ethertype));
		
		memcpy(&oprecieve,reply+6, sizeof(oprecieve));
		oprecieve = ntohs(oprecieve);
		
		memcpy(ip_src, reply+14, sizeof(ip_src));

		memcpy(ip_dst, reply+24, sizeof(ip_dst));
		if (ethertype == ETHERTYPE && oprecieve == 2
			&& (orig_ip[0] == ip_dst[0] && orig_ip[1] == ip_dst[1] && orig_ip[2] == ip_dst[2] && orig_ip[3] == ip_dst[3])
		) {
			printf("IP: %d.%d.%d.%d\t", ip_src[0], ip_src[1], ip_src[2], ip_src[3]);
			printf("MAC origem:  %02x:%02x:%02x:%02x:%02x:%02x\n", 
                        mac_src[0], mac_src[1], mac_src[2], mac_src[3], mac_src[4], mac_src[5]);
			printf("\n");
		}
	}

	close(fd);
	return 0;
}

