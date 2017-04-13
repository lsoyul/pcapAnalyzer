#include <stdio.h>
#include <pcap.h>
#include <time.h>

#include "headerStructures.h"

#pragma comment(lib, "ws2_32.lib")

#define LINE_LEN 16
#define MAX_PACKET_LIMIT 500


// Callback function when a packet captured
void dispatcher_handler(u_char *, const struct pcap_pkthdr *, const u_char *);


void ViewPktHeader(struct pcap_pkthdr* header);
void ViewEthernet(u_char* pktBuf);

void ViewIP(u_char* pktBuf);
//void ViewARP(u_char* pktBuf);

static u_int packetNumber = 1;
static const char filepath[] = "myCapture2.pcap";

FILE *savefp;	// for save

int main()
{
	pcap_t *fp;
	char errbuf[PCAP_ERRBUF_SIZE];
	
	savefp = fopen("result2.txt", "w");

	/* Open the capture file */
	if ((fp = pcap_open_offline(filepath,			// name of the device
						 errbuf						// error buffer
						 )) == NULL)
	{
		fprintf(stderr,"\nUnable to open the file %s.\n", filepath);
		return -1;
	}

	/* read and dispatch packets until MAX_PACKET_LIMIT */
	pcap_loop(fp, MAX_PACKET_LIMIT, dispatcher_handler, NULL);

	pcap_close(fp);

	fclose(savefp);
	return 0;
}



void dispatcher_handler(u_char *temp1, 
						const struct pcap_pkthdr *header, 
						const u_char *pkt_data)
{
	u_int i=0;
	
	/*
	 * unused variable
	 */
	(VOID*)temp1;

	printf("<Packet No.%ld>\n", packetNumber);
	fprintf(savefp, "<Packet No.%ld>\n", packetNumber);
	
	ViewPktHeader(header);
	ViewEthernet(pkt_data);

	/* Print the packet */
	//for (i=1; (i < header->caplen + 1 ) ; i++)
	//{
	//	printf("%.2x ", pkt_data[i-1]);
	//	if ( (i % LINE_LEN) == 0) printf("\n");
	//}
	printf("\n===================================================\n");
	printf("\n\n");	

	fprintf(savefp, "\n===================================================\n");
	fprintf(savefp, "\n\n");

	packetNumber++;
}

void ViewPktHeader(struct pcap_pkthdr* header)
{
	time_t sec = header->ts.tv_sec;
	struct tm* timeInfo;

	//time(&sec);
	timeInfo = localtime(&sec);

	int cYear = timeInfo->tm_year + 1900;
	int cMonth = timeInfo->tm_mon + 1;
	/* print pkt timestamp and pkt len */
	printf("===================PACKET HEADER===================\n");
	printf("Arrival local time and date: %d년%d월%d일  %d:%d:%d.%d\n", cYear, cMonth, timeInfo->tm_mday, timeInfo->tm_hour, timeInfo->tm_min, timeInfo->tm_sec, header->ts.tv_usec);
	printf("Timeval sec:%ld  Timeval usec:%ld  Length of this Packet:(%ld bytes)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
	printf("====================PACKET DATA====================\n");

	fprintf(savefp,"===================PACKET HEADER===================\n");
	fprintf(savefp,"Arrival local time and date: %d년%d월%d일  %d:%d:%d.%d\n", cYear, cMonth, timeInfo->tm_mday, timeInfo->tm_hour, timeInfo->tm_min, timeInfo->tm_sec, header->ts.tv_usec);
	fprintf(savefp,"Timeval sec:%ld  Timeval usec:%ld  Length of this Packet:(%ld bytes)\n", header->ts.tv_sec, header->ts.tv_usec, header->len);
	fprintf(savefp,"====================PACKET DATA====================\n");

}

void ViewEthernet(u_char* pktBuf)
{
	/*
		srcMAC			6 bytes
		destMAC			6 bytes
		protocolType	2 bytes
		~ DATA
	*/

	printf("\n<Ethernet Header>\n");
	fprintf(savefp,"\n<Ethernet Header>\n");
	s_ethernet *ether = (s_ethernet *)pktBuf;

	printf("SrcMAC: ");
	fprintf(savefp, "SrcMAC: ");

	for (int i = 0; i < MAC_ADDR_LEN; i++)
	{
		printf("%.2x", ether->src_mac[i]);
		fprintf(savefp, "%.2x", ether->src_mac[i]);
		if (i < MAC_ADDR_LEN - 1) { printf(":"); fprintf(savefp, ":"); }
	}

	printf("  ->  DstMAC: ");
	fprintf(savefp, "  ->  DstMAC: ");

	for (int i = 0; i < MAC_ADDR_LEN; i++)
	{
		printf("%.2x", ether->dest_mac[i]);
		fprintf(savefp, "%.2x", ether->dest_mac[i]);
		if (i < MAC_ADDR_LEN - 1) { printf(":"); fprintf(savefp, ":"); }
	}

	printf("\nProtocol type: %#x\n", exchangeByteOrder(ether->type));
	fprintf(savefp, "\nProtocol type: %#x\n", exchangeByteOrder(ether->type));

	// Consider IP and ARP
	// 0x800 == IP
	// 0x806 == ARP
	switch (exchangeByteOrder(ether->type))
	{
	case 0x800:
		ViewIP(pktBuf + sizeof(s_ethernet));	// give the next position of s_ethernet size
		break;
	//case 0x806:
	//	ViewARP(pktBuf + sizeof(s_ethernet));
	//	break;
	default:
		printf("!Not supported protocol!\n");
		fprintf(savefp, "!Not supported protocol!\n");
		break;
	}

	printf("\n");
}


void ViewIP(u_char* pktBuf)
{
	IN_ADDR addr;

	s_ip* ip = (s_ip*)pktBuf;

	printf("\n<IPv4 Header>\n");
	fprintf(savefp, "\n<IPv4 Header>\n");

	addr.s_addr = ip->src_IP_address;
	printf("SrcIP: %s  ->  ", inet_ntoa(addr));
	fprintf(savefp, "SrcIP: %s  ->  ", inet_ntoa(addr));

	addr.s_addr = ip->dest_IP_address;
	printf("DstIP: %s\n", inet_ntoa(addr));

	printf("IP Header Length: %d (%d bytes)\n", ip->hlen, ip->hlen*4);
	printf("Version: %d\n", ip->version);
	printf("Total Length(IP header + Data): %d bytes\n", exchangeByteOrder(ip->totLength));
	printf("ID: %d\n", exchangeByteOrder(ip->id));

	printf("Flags: ");

	fprintf(savefp, "DstIP: %s\n", inet_ntoa(addr));
	fprintf(savefp, "IP Header Length: %d (%d bytes)\n", ip->hlen, ip->hlen * 4);
	fprintf(savefp, "Version: %d\n", ip->version);
	fprintf(savefp, "Total Length(IP header + Data): %d bytes\n", exchangeByteOrder(ip->totLength));
	fprintf(savefp, "ID: %d\n", exchangeByteOrder(ip->id));
	fprintf(savefp, "Flags: ");

	if (DONT_FRAG(ip->frag))
	{
		printf("Don't Fragment(DF)\n");
		fprintf(savefp, "Don't Fragment(DF)\n");
	}
	else
	{
		printf("MF -> ");
		fprintf(savefp, "MF -> ");
		if (MORE_FRAG(ip->frag) == 0)
		{
			printf("Last fragment, ");
			fprintf(savefp, "Last fragment, ");
		}
		printf("offset: %d\n", FRAG_OFFSET(ip->frag));
		fprintf(savefp, "offset: %d\n", FRAG_OFFSET(ip->frag));
	}

	printf("Protocol: ");
	fprintf(savefp, "Protocol: ");

	switch (ip->protocol)
	{
	case 1:
		printf("ICMP\n");
		fprintf(savefp, "ICMP\n");
		break;
	case 2:
		printf("IGMP\n");
		fprintf(savefp, "IGMP\n");
		break;
	case 6:
		printf("TCP\n");
		fprintf(savefp, "TCP\n");

		break;
	case 17:
		printf("UDP\n");
		fprintf(savefp, "UDP\n");
		break;
	case 89:
		printf("OSPF\n");
		fprintf(savefp, "OSPF\n");
		break;
	default:
		printf("Not supported");
		fprintf(savefp, "Not supported");
		break;
	}
}

//void ViewARP(u_char* pktBuf)
//{
//
//}