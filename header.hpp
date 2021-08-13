/************************************************************************
 * File:	header.hpp
 * Project:	Packet sniffer
 * Subject: Computer Communications and Networks(IPK)
 * Author:	Damián Sova (xsovad06)
 * Date:	1.5.2020
 ***********************************************************************/

// Libraries
#include <iostream>					// cout
#include <ifaddrs.h>				// getifaddrs()
#include <iomanip>					// setw(), setfill()
#include <getopt.h>					// getopt_long()
#include <pcap.h>					// pcap_lookupnet(), pcap_open_live(), pcap_datalink(),
									// pcap_compile(), pcap_setfilter(), pcap_loop(),
									// pcap_geterr(), pcap_close()
#include <string.h>					// strcpy()
#include <arpa/inet.h>				// inet_ntoa()
#include <netdb.h>					// getnameinfo()

// GLOBALS
unsigned int num = 1;				// Number o capturing packets, default 1
std::string filter_port;			// String representing port filter expression
std::string filter_protocol;		// String representing protocol filter expression
bool tcp = false;					// Value represent searching for TCP packets 
bool udp = false;					// Value represent searching for UDP packets
char *interface;					// Array representing name of interface device

#define SNAP_LEN		1518		// Maximum bytes per packet to capture
#define SIZE_ETHERNET	14			// Const size of ethernet heather
#define ETHER_ADDR_LEN	6			// Const size of ethernet address

// IP header structure
struct sniff_ip {
	unsigned char  ip_vhl;			// Version << 4 | header length >> 2 
	unsigned char  ip_tos;			// Type of service 
	unsigned short ip_len;			// Total length 
	unsigned short ip_id;			// Identification 
	unsigned short ip_off;			// Fragment offset field 
	#define IP_RF 0x8000			// Reserved fragment flag 
	#define IP_DF 0x4000			// Dont fragment flag 
	#define IP_MF 0x2000			// More fragments flag 
	#define IP_OFFMASK 0x1fff		// Mask for fragmenting bits 
	unsigned char  ip_ttl;			// Time to live 
	unsigned char  ip_p;			// Protocol 
	unsigned short ip_sum;			// Checksum 
	struct in_addr ip_src, ip_dst;	// Source and dest address 
};

#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)

// Universal header structure for source and destination port
struct sniff_hdr {
	uint16_t src_port;		// source port 
	uint16_t dst_port;		// destination port 
};

// Class for demonstraition of object programing
class Packet_time {
	private:
		int hours;						// Hours 
		int minutes;					// Minutes 
		int seconds;					// Seconds 
		suseconds_t u_seconds;			// Micro seconds

	public:
		// Function set values of object Packet_time
		void set_time(int hh, int mm, int ss, suseconds_t us);
		// Function for printing time from the packet
		void print_time();
};

// Function for printing help messagewhen only parameter --help/-h is set
void print_help();

// Function for printing time from the packet
void print_packet_time(int hours, int minutes, int seconds, suseconds_t useconds);

// Function process program arguments an fill certain global variables
int arg_processor(int argc, char** argv);

// Process header layers of spacket and call function print_packet() 
void packet_processor(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet);

//Function print whole packet by calling function print_hexa_ascii_line
void print_packet(const unsigned char *packet, int len);

// Function print one line content of packet, first hexadecimal coded then like ascii code
int print_hex_ascii(const unsigned char *packet, int len, int printed_bytes);