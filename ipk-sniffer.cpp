/************************************************************************
 * File:	ipk-sniffer.cpp
 * Project:	Packet sniffer
 * Subject: Computer Communications and Networks(IPK)
 * Author:	Damián Sova (xsovad06)
 * Date:	1.5.2020
 ***********************************************************************/

// Included header with libraries, global variables, constants,
// struct declaration and function prototypes
#include "header.hpp"

using namespace std;

/************************************************************************
 ****************************** MAIN FUNCTION ***************************
 ***********************************************************************/
int main(int argc, char *argv[])
{
	// Proccessing program arguments
	if (arg_processor(argc, argv) != 0) {
		fprintf(stderr, "Incorrect program arguments.\n");
		exit(EXIT_FAILURE);
	}

	char errbuf[PCAP_ERRBUF_SIZE];		// Error buffer

	// Print interface devices if no one set in program arguments
	if (interface == NULL) {
		pcap_if_t *all_dev;				// First node of the list with interface devices
		pcap_if_t *dev;					// Variable used in for cycle
		
		// Function searches for interface devices
		if (pcap_findalldevs(&all_dev, errbuf) != 0) {
			cout << "Fail while searching for interface device." << endl;
		}

		// No device was found
		if (all_dev == NULL) {
			cout << "No device available." << endl;	
		}

		// Print all founded devices
		cout << "Posible interface devices for sniffing from pcap:" << endl;
		for (dev = all_dev; dev; dev = dev->next) {
			cout << "   Device name: " << dev->name << endl; 
		}

		// Cleanup
		pcap_freealldevs(all_dev);
		pcap_freealldevs(dev);
		return 0;
	}

	pcap_t *handle;						// Packet capture handle
	struct bpf_program fp;				// Compiled filter program (expression)
	bpf_u_int32 mask;					// Subnet mask
	bpf_u_int32 net;					// IP

	// Get network number and mask associated with capture device
	if (pcap_lookupnet(interface, &net, &mask, errbuf) == -1) {
		fprintf(stderr, "Couldn't get netmask for device: %s\n", errbuf);	
		exit(EXIT_FAILURE);
	}

	// Open interface device for sniffing
	handle = pcap_open_live(interface, SNAP_LEN, 1, 1000, errbuf);
	if (handle == NULL) {
		fprintf(stderr, "Couldn't open device %s: %s\n", interface, errbuf);
		exit(EXIT_FAILURE);
	}

	// Capturing on an Ethernet device
	if (pcap_datalink(handle) != DLT_EN10MB) {
		fprintf(stderr, "%s is not an Ethernet.\n", interface);
		exit(EXIT_FAILURE);
	}

	// Set string filter expression for certain protocol
	if (tcp and !udp) {
		filter_protocol = "tcp";
	}	
	else if (!tcp and udp) {
		filter_protocol = "udp";
	}	

	// If at least one is set, set filter 
	if (filter_port != "" or filter_protocol != "") {
		// Create string if both are set: "<protocol> port <port_number>"
		filter_protocol.append(" ");
		filter_protocol.append(filter_port);
		
		// Declaring character array 
		char filter_pattern[filter_protocol.length() + 1];
		// Copying the content from the string to char array 
		strcpy(filter_pattern, filter_protocol.c_str());

		// Compile the filter expression
		if (pcap_compile(handle, &fp, filter_pattern, 0, net) == -1) {
			fprintf(stderr, "Couldn't parse filter %s: %s\n", filter_pattern, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}

		// Set compiled filter
		if (pcap_setfilter(handle, &fp) == -1) {
			fprintf(stderr, "Couldn't install filter %s: %s\n", filter_pattern, pcap_geterr(handle));
			exit(EXIT_FAILURE);
		}
	}

	// Set callback function packet_processor(), heart of packet processing
	pcap_loop(handle, num, packet_processor, NULL);

	// Cleanup
	//pcap_freecode(&fp);  -- make memmory errors
	pcap_close(handle);

	// Successful run of the program
	return 0;
}

/************************************************************************
 * **************** IMPLEMENTATION OF ADDITIONAL FUNCTIONS **************
 * *********************************************************************/

// Function for printing help message when only parameter --help/-h is set
void print_help()
{
	cout <<
	"-n <n>:		Set number of processed packets\n"
	"-i <string>:	Set interface for searching pakets\n"
	"-p <port_n>:	Set port number for searching packets\n"
	"--tcp/-t:		Searching for TCP packets\n"
	"--udp/-u:		Searching for UDP packets\n"
	"--help/-h:		Show help\n";
	exit(EXIT_SUCCESS);
}

// Function process program arguments an fill certain global variables
int arg_processor(int argc, char** argv)
{
	unsigned int arg_processed = 0;				// Number of actualy proccessed arguments

	const char* const short_opts = "i:p:tun:h";	// Short arguments options
	const option long_opts[] = {
			{"tcp", no_argument, nullptr, 't'},
			{"udp", no_argument, nullptr, 'u'},
			{"help", no_argument, nullptr, 'h'},
			{nullptr, no_argument, nullptr, 0}
	};											// Long arguments options 

	// Till all arguments are processed
	while (true)
	{
		// Function for parsing program arguments
		const auto opt = getopt_long(argc, argv, short_opts, long_opts, nullptr);
		// End of the parsing
		if (-1 == opt) {
			return 0;
		}
		// Parsing options
		switch (opt) {
			// -i <interface>
			case 'i':
				interface = optarg;
				arg_processed++;
				break;
			// -p <port_number>
			case 'p':
				try {
					filter_port = "port ";
					// Append port number to the string "port <port_number>"
					filter_port += to_string(stoi(optarg));
				}
				catch(...) {
					return -1;
				}
				arg_processed++;
				break;
			// -t/--tcp
			case 't':
				tcp = true;
				arg_processed++;
				break;
			// -u/--udp
			case 'u':
				udp = true;
				arg_processed++;
				break;
			// -n <packet_count>
			case 'n':
				try {
					num = (unsigned int)stoi(optarg);
				}
				catch(...) {
					return -1;
				}
				arg_processed++;
				break;
			// -h/--help
			case 'h':
				if (arg_processed == 0) {
					print_help();
					exit(0);
				}
				return -1;
				
			// Other options raise argument error
			default:
				return -1;
		}
	}
}

// Process header layers of spacket and call function print_packet() 
void packet_processor(unsigned char *args, const struct pcap_pkthdr *header, const unsigned char *packet)
{
	const struct sniff_ip *ip;						// The IP header
	const struct sniff_hdr *protocol_header;		// The universal protocol header(for TCP and UDP)

	int size_ip;									// Size of IP header
	int size_packet = header->len;					// Size of the whole packet

	int time_in_sec = header->ts.tv_sec % 86400;	// Real time in second
 	int hours = (time_in_sec / 3600) + 2;			// Get hours from time above
	int minutes = (time_in_sec % 3600) / 60;		// Get minutes from time above
	int seconds = (time_in_sec % 3600) % 60;		// The rest are seconds

	unsigned int src_port_n;
	unsigned int dst_port_n;

	Packet_time Time;								// Create instace of class Packet_time
	// Set Time values
	Time.set_time(hours, minutes, seconds, header->ts.tv_usec);

	// Initialize IP header
	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
	size_ip = IP_HL(ip)*4;
	if (size_ip < 20) {
		cout <<"Invalid IP header length: " << size_ip << " bytes" << endl << endl;
		return;
	}

	const char *src_addr = inet_ntoa(ip->ip_src);	// Source IP address
	const char *dst_addr = inet_ntoa(ip->ip_dst);	// Destination IP address

	char src_host[1024];							// Array for domain name of source IP address
	char dst_host[1024];							// Array for domain name of destination IP address
	struct sockaddr_in socketAddress;				// Structure for internet socet address
	socketAddress.sin_family = AF_INET; 			// Using IPv4
	
	// Convert IPv4 addresses from text to binary form
	inet_pton(AF_INET, src_addr, &(socketAddress.sin_addr));
	// Translate IP address to domain name, if fail use ip address
	if (getnameinfo((struct sockaddr *)&socketAddress, sizeof(socketAddress), src_host, 1024, NULL, 0, NI_NAMEREQD)) {
		strcpy(src_host, src_addr); 
	}
	
	// Convert IPv4 addresses from text to binary form
	inet_pton(AF_INET, dst_addr, &(socketAddress.sin_addr));
	// Translate IP address to domain name, if fail use ip address
	if (getnameinfo((struct sockaddr *)&socketAddress, sizeof(socketAddress), dst_host, 1024, NULL, 0, NI_NAMEREQD)) {
		strcpy(dst_host, dst_addr); 
	}

	// Both --tcp/-t or --udp/-u was set or not 
	if (tcp == udp) {
		switch (ip->ip_p) {
			case IPPROTO_TCP:
			case IPPROTO_UDP:
				// Initialize protocol header including port numbers
				protocol_header = (struct sniff_hdr*)(packet + SIZE_ETHERNET + size_ip);
				src_port_n = ntohs(protocol_header->src_port);
				dst_port_n = ntohs(protocol_header->dst_port);
				// Print time from packet
				Time.print_time();
				// Print beginning line of processing packet
				cout << src_host << " : ";
				printf("%u > ", src_port_n);
				cout << dst_host << " : ";
				printf("%u", dst_port_n);
				cout << endl;
				// Print body of packet
				print_packet(packet, size_packet);
		
			default:
				return;
		}
	}
	// Only one of them was set as program argument(tcp or udp)
	else {
		// Initialize protocol header including port numbers
		protocol_header = (struct sniff_hdr*)(packet + SIZE_ETHERNET + size_ip);
		src_port_n = ntohs(protocol_header->src_port);
		dst_port_n = ntohs(protocol_header->dst_port);
		// Print time from packet
		Time.print_time();
		// Print beginning line of processing packet
		cout << src_host << " : ";
		printf("%u > ", src_port_n);
		cout << dst_host << " : ";
		printf("%u", dst_port_n);
		cout << endl;
		// Print body of packet
		print_packet(packet, size_packet);
	}
	return;
}

// Print whole packet 
void print_packet(const unsigned char *packet, int len)
{

	int len_rem = len;
	int line_width = 16;							// Number of bytes per line
	int line_len;
	const unsigned char *ch = packet;
	int printed_bytes = 0;
	
	// Save outstream flag before using "cout << hex"
	std::ios_base::fmtflags f(cout.flags());

	// Data spans multiple lines
	for ( ;; ) {
		// compute current line length
		line_len = line_width % len_rem;
		// print line
		printed_bytes = print_hex_ascii(ch, line_len, printed_bytes);
		// compute total remaining
		len_rem = len_rem - line_len;
		// shift pointer to remaining bytes to print
		ch = ch + line_len;

		// check if we have line width chars or less
		if (len_rem <= line_width) {
			// print last line and get out
			printed_bytes = print_hex_ascii(ch, len_rem, printed_bytes);
			break;
		}
	}
	// New line after whole packet is printed
	cout << endl;
	// Restore saved flag for normal printing 
	cout.flags( f );

	return;
}


// Print packet in rows of 16 bytes: number of printed bytes: hex ascii
int print_hex_ascii(const unsigned char *packet, int len, int printed_bytes)
{
	int i;
	int gap;
	const unsigned char *ch;

	// Number of printed bytes on line in hexadecimal representation
	cout << "0x" << setw(4) << setfill('0') << hex << printed_bytes << ": ";
	
	// Print hexadecimal representation of data
	ch = packet;
	for(i = 0; i < len; i++) {
		cout << setw(2) << setfill('0') << hex << (int)(*ch) << " ";
		ch++;
		printed_bytes++;
		// Extra space after 8th member
		if (i == 7) {
			cout << " ";
		}
	}
	// Print space to handle line less than 8 bytes
	if (len < 8) {
		cout << " ";
	}
	// Fill gap with spaces if not full line
	if (len < 16) {
		gap = 16 - len;
		for (i = 0; i < gap; i++) {
			cout << "   ";
		}
	}
	// Print space between hex and ascii data
	cout << " ";
	
	// Print ASCII character(if printable)
	ch = packet;
	for(i = 0; i < len; i++) {
		if (isprint(*ch))
			cout << *ch;
		else
			cout << ".";
		ch++;
		// Extra space after 8th member
		if (i == 7) {
			cout << " ";
		}
	}
	// New line after one line of the packet is printed
	cout << endl;

	return printed_bytes;
}

// Function set values of object Packet_time
void Packet_time::set_time(int hh, int mm, int ss, suseconds_t us) {
	hours =	hh;
	minutes =	mm;
	seconds =	ss;
	u_seconds = us;
}

// Function for printing time from the packet
void Packet_time::print_time() {
	cout << setw(2) << setfill('0') << hours << ":" << setw(2) << setfill('0') << minutes;
	cout  << ":" << setw(2) << setfill('0') << seconds << "."; 
	cout << u_seconds << " ";
}
