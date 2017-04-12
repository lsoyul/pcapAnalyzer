#pragma once
#define MAC_ADDR_LEN 6

u_short exchangeByteOrder(u_short value)
{
	return(value << 8) | (value >> 8);	//상위 바이트와 하위바이트 위치 교환
}


typedef struct _ethernet
{
	u_char dest_mac[MAC_ADDR_LEN];		// Destination MAC address
	u_char src_mac[MAC_ADDR_LEN];		// Source MAC address
	u_short type;						// Protocol type (IP, ARP ...etc)
}s_ethernet;


typedef struct _ip
{
	u_char hlen : 4;		// header length	(This variable is 4 bits.)
	u_char version : 4;		// version			(This variable is 4 bits.)
	u_char DS;				// TOS (Type of service)
	u_short totLength;		// Total length (header + data)
	u_short id;				// Identification
	u_short frag;			// 3bit:Flags 13bits:Fragmentation offset

#define DONT_FRAG(frag)		(frag & 0x40)
#define MORE_FRAG(frag)		(frag & 0x20)
#define FRAG_OFFSET(frag)	(exchangeByteOrder(frag) & (~0x6000))

	u_char TTL;				// Time to live
	u_char protocol;		// for upper layer
	u_short checksum;		// header checksum (detect error)

	u_int src_IP_address;	// source IP address
	u_int dest_IP_address;	// destination IP address
}s_ip;

