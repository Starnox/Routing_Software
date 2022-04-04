#include "queue.h"
#include "skel.h"

#define MAX_NUM_ADDRESSES 100005
#define ARP_TABLE_LOCATION "arp_table.txt"


// works in O(n) time
struct route_table_entry *get_best_route(struct in_addr dest_ip, 
								struct route_table_entry *rtable, int rtable_len) {
    size_t idx = -1;	

	// go through every entry of the routing table
    for (size_t i = 0; i < rtable_len; i++) {
		// checks if the entry matches the destination ip using the AND operation on the mask
        if ((dest_ip.s_addr & rtable[i].mask) == rtable[i].prefix) {

			// if it is the first time we set the ip
	    	if (idx == -1)
				idx = i;

			/*
			Checks if we can find a better prefix
			we first have to convert from network order to host byte order
			in order to do comparisons on our little endian machine
			the bigger the netmask -> the more accurate
			*/
	    	else if (ntohl(rtable[idx].mask) < ntohl(rtable[i].mask))
				idx = i;
		}
    }
    
	// if we haven't found an entry
    if (idx == -1)
        return NULL;

	// otherwise we return a pointer to that specific entry
    else
        return &rtable[idx];
}

struct arp_entry* get_next_hop(uint32_t dest_ip, struct arp_entry* arp_table, int arp_table_length){
	// iterates through each entry

	for(size_t i = 0; i < arp_table_length; ++i){
		// if we found and entry that matches
		if(ntohl(dest_ip) == ntohl(arp_table[i].ip))
			return &arp_table[i];
	}
	// No match
	return NULL;
}
// TODO implement a more efficient search


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	// extract the routing table from the argument list -> argv[1]
	char *routing_table_location = argv[1];

	// declare and initialise the routing table
	struct route_table_entry* rtable = malloc(sizeof(struct route_table_entry) * MAX_NUM_ADDRESSES);
	int rtable_length = read_rtable(routing_table_location, rtable);

	// declare and initialise the arp table
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100);
	int arp_table_legth = parse_arp_table(ARP_TABLE_LOCATION, arp_table);

	
	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		
		// The code for basic forwarding will be very similar to the one given for lab4
		
		struct ether_header *eth_header = (struct ether_header *) m.payload;

		// declare the ip header and destination ip
		struct iphdr *ip_header;
		struct in_addr dest_ip;

		// check if the packet recieved is if type Ethertype_IPV4
		if(ntohs(eth_header->ether_type) == 0x0800){
			
			// we extract the ip header
			ip_header = (struct iphdr *) (m.payload + sizeof(struct ether_header));
			
			// if the checksum of the ip header is not 0 then we drop the packet
			if(ip_checksum((void *)ip_header, sizeof(struct iphdr)) != 0)
				continue;

			// if the time to live got to 0 then we also drop the packet
			if(ip_header->ttl == 0)
				continue;

			// get the destination ip
			dest_ip.s_addr = ip_header->daddr;

			// get the best route using the algorithm we wrote earlier
			struct route_table_entry* best_route = get_best_route(dest_ip, rtable, rtable_length);

			// if we haven't found any valid route we drop the packet
			if(best_route == NULL)
				continue;
			
			// gets the mac address of the next hop
			struct arp_entry* next_hop = get_next_hop(best_route->next_hop, arp_table, arp_table_legth);

			// if we haven't found the next hop we drop the packet
			if(next_hop == NULL)
				continue;

			// decrement time to live
			ip_header->ttl--;

			// set checksum to 0 in order to recalculate it
			ip_header->check = 0;

			// recalculate checksum
			ip_header->check = ip_checksum((void *)ip_header, sizeof(struct iphdr));

			// put in the ethernet header the new destination mac (it has 6 bytes)
			memcpy(eth_header->ether_dhost, next_hop->mac, 6);
			
			// get the mac address of the source (i.e the interface from which we will send the packet)
			// set it in the ethernet header before sending it
			get_interface_mac(best_route->interface, eth_header->ether_shost);

			// set the interface of the packet
			m.interface = best_route->interface;

			// sending the packet on the specified interface
			send_packet(&m);

			// TODO implement dynamic arp table

			// Using the hardcoded table for now

		}


	}
}
