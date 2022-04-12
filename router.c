#include "queue.h"
#include "skel.h"
#include "trie.h"

#define MAX_NUM_ADDRESSES 100005
#define ARP_TABLE_LOCATION "arp_table.txt"

uint8_t ether_broadcast[6] = {0xff,0xff,0xff,0xff,0xff,0xff};

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


// get next hop from the static arp table
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

packet *create_arp_reply(packet m){
	// get the headers of the package
	struct ether_header *eth_header = (struct ether_header *) m.payload;
	struct arp_header *arp_h = (struct arp_header *)(m.payload + sizeof(struct ether_header));

	char *char_router_address;
	char_router_address = get_interface_ip(m.interface);
	uint32_t router_address;
	int code = inet_pton(AF_INET, char_router_address, &router_address);
	if(code != 1)
		printf("Error while converting address");

	packet *new_packet = (packet *) malloc(sizeof(packet));
	// add the interface to the packet
	new_packet->interface = m.interface;
	new_packet->len = sizeof(struct ether_header) + sizeof(struct arp_header);

	memset(new_packet->payload, 0 , sizeof(new_packet->payload));

	// declare the ethernet and arp headers and point them at the right positions
	struct ether_header *eth_header_r = (struct ether_header *) new_packet->payload;
	struct arp_header *arp_header_r = (struct arp_header *)(new_packet->payload +
									sizeof(struct ether_header));
	
	// fill the two headers information (similar to arp_request)

	// ETHERNET
	memcpy(eth_header_r->ether_dhost, eth_header->ether_shost, 6); // destination is the source of the package
	get_interface_mac(m.interface, eth_header_r->ether_shost); // source is the router
	eth_header_r->ether_type = htons(ETHERTYPE_ARP);

	// ARP
	arp_header_r->htype = htons(1);
	arp_header_r->ptype = htons(ETHERTYPE_IP);
	arp_header_r->hlen = 6;
	arp_header_r->plen = 4;
	arp_header_r->op = htons(2); // op for arp reply
	
	// extract the source MAC and source IP and put them now as target
	memcpy(arp_header_r->tha, arp_h->sha, 6);
	arp_header_r->tpa = arp_h->spa;

	// set the source ip and MAC (router)
	arp_header_r->spa = router_address;
	get_interface_mac(m.interface, arp_header_r->sha);


	// return the packet
	return new_packet;
}

// creates and returns an arp request packet for the specified ip
packet* create_arp_request(uint32_t dest_ip, int interface){
	// initialise a new packet
	packet *new_packet = (packet *) malloc(sizeof(packet));

	// get router address
	char * char_router_address = get_interface_ip(interface);
	uint32_t router_address;
	int code = inet_pton(AF_INET, char_router_address, &router_address);
	if(code != 1)
		printf("Error while converting address");

	// add the interface to the packet
	new_packet->interface = interface;
	new_packet->len = sizeof(struct ether_header) + sizeof(struct arp_header);

	// set FF:FF:FF:FF:FF:FF as the destionation mac (broadcast)
	struct ether_header *eth_header = (struct ether_header *) new_packet->payload;
	memcpy(eth_header->ether_dhost, ether_broadcast, sizeof(ether_broadcast));
	
	// get the router mac address
	uint8_t router_mac[ETH_ALEN];
	get_interface_mac(interface, router_mac);

	// set the the source mac address
	memcpy(eth_header->ether_shost, router_mac, sizeof(router_mac));

	// set ether type
	eth_header->ether_type = htons(ETHERTYPE_ARP);

	struct arp_header *arp_h = (struct arp_header *)(new_packet->payload +
									sizeof(struct ether_header));

	// set necessary info for the arp frame
	arp_h->htype = htons(1);
	arp_h->ptype = htons(ETHERTYPE_IP);
	arp_h->hlen = 6;
	arp_h->plen = 4;
	arp_h->op = htons(1); // op for arp request
	memcpy(arp_h->sha, router_mac, sizeof(router_mac));

	arp_h->spa = router_address;
	memset(arp_h->tha, 0, sizeof(router_mac)); // target mac address is 00:00:00:00:00:00
	arp_h->tpa = dest_ip;

	
	return new_packet;
}

packet *create_icmp_packet(int type_of_packet, packet m){

	// extract headers
	struct ether_header *eth_header = (struct ether_header *) m.payload;
	struct iphdr *ip_header = (struct iphdr *) (m.payload + sizeof(struct ether_header));
	struct icmphdr *icmp_header = (struct icmphdr *) (m.payload
									 + sizeof(struct ether_header) + sizeof(struct iphdr));

	// get router ip address
	char *char_router_address;
	char_router_address = get_interface_ip(m.interface);
	uint32_t router_address;
	int code = inet_pton(AF_INET, char_router_address, &router_address);
	if(code != 1)
		printf("Error while converting address");

	// create the packet
	packet *new_packet = (packet *) malloc(sizeof(packet));
	memset(new_packet->payload, 0 , sizeof(new_packet->payload));

	// set the fields
	new_packet->interface = m.interface;
	new_packet->len = sizeof(struct ether_header) + sizeof(struct iphdr)
					 + sizeof(struct icmphdr);

	// point the headers to the correct positions
	struct ether_header *ether_header_r = (struct ether_header *) new_packet->payload;
	struct iphdr *ip_header_r = (struct iphdr*) (new_packet->payload + sizeof(struct ether_header));
	struct icmphdr *icmp_header_r = (struct icmphdr *) (new_packet->payload
									 + sizeof(struct ether_header) + sizeof(struct iphdr));


	// fill ether header information
	// the destination will be the device that sent the message
	memcpy(ether_header_r->ether_dhost, eth_header->ether_shost, 6);

	// the source will be the router (in this case the reciever of the original packet)
	memcpy(ether_header_r->ether_shost, eth_header->ether_dhost, 6);
	ether_header_r->ether_type = htons(ETHERTYPE_IP); // type ipv4

	// fill ip header
	ip_header_r->version = 4;
	ip_header_r->ihl = 5;
	ip_header_r->tos = 0;
	ip_header_r->id = htons(25);
	ip_header_r->ttl = ip_header->ttl;
	ip_header_r->protocol = IPPROTO_ICMP;
	ip_header_r->tot_len = htons(sizeof(struct iphdr) + sizeof(struct icmphdr));

	// calculate checksum
	ip_header_r->check = 0;
	ip_header_r->check = ip_checksum((void *)ip_header_r, sizeof(struct iphdr));
	
	// set destination and source
	ip_header_r->daddr = ip_header->saddr;
	ip_header_r->saddr = router_address;

	// fill icmp header
	icmp_header_r->type = type_of_packet;
	icmp_header_r->code = 0;

	// depending on the type of packet we need to create we will update the fields
	if(type_of_packet == ICMP_ECHOREPLY){
		icmp_header_r->un.echo.sequence = icmp_header->un.echo.sequence;
		icmp_header_r->un.echo.id = icmp_header->un.echo.id;
	}
	else{
		icmp_header_r->un.echo.sequence = 0;
		icmp_header_r->un.echo.id = 0;
	}

	// after all this is set we need to calculate the checksum
	icmp_header_r->checksum = 0;
	icmp_header_r->checksum = ip_checksum((void *)icmp_header_r, sizeof(struct icmphdr));

	return new_packet;
}

// Route search using Trie (way more efficient)
TrieNodePointer create_routing_trie(struct route_table_entry *rtable, int rtable_len){
	TrieNodePointer newTrie = InitialiseTrieNode();
	
	if(newTrie == NULL)
	{
		fprintf(stderr, "Error while initialising");
		return NULL;
	}

	for (size_t i = 0; i < rtable_len; i++) {
		InsertNode(newTrie, &rtable[i]);
	}
	
	return newTrie;
}

void update_and_send(packet *m, struct iphdr *ip_header,struct ether_header *eth_header,
				struct route_table_entry *best_route, struct arp_entry* next_hop ){
	// decrement time to live
	ip_header->ttl--;

	// recalculate checksum using rfc 1624 equation
	// the method and code was found on https://www.rfc-editor.org/rfc/pdfrfc/rfc1141.txt.pdf
	uint16_t new_check_sum = ntohs(ip_header->check) + 0x100;
	ip_header->check = htons(new_check_sum + (new_check_sum >> 16));

	// put in the ethernet header the new destination mac (it has 6 bytes)
	memcpy(eth_header->ether_dhost, next_hop->mac, 6);
	
	// get the mac address of the source (i.e the interface from which we will send the packet)
	// set it in the ethernet header before sending it
	get_interface_mac(best_route->interface, eth_header->ether_shost);

	// set the interface of the packet
	m->interface = best_route->interface;
	
	// sending the packet on the specified interface
	send_packet(m);
}

// TODO create arp request only one time

void forward_ipv4_packet(packet *pckt, TrieNodePointer routing_trie, struct arp_entry *arp_table,
						int arp_table_length, queue pckt_queue, struct ether_header *eth_header){
	struct iphdr *ip_header;
	struct in_addr dest_ip;
	// we extract the ip header
	ip_header = (struct iphdr *) (pckt->payload + sizeof(struct ether_header));
	
	// if the checksum of the ip header is not 0 then we drop the packet
	if(ip_checksum((void *)ip_header, sizeof(struct iphdr)) != 0)
		return;

	// if the time to live got to 0 then we also drop the packet
	if(ip_header->ttl <= 1){
		// create time exceeded icmp packet and send it
		packet *icmp_timeout = create_icmp_packet(ICMP_TIME_EXCEEDED, *pckt);
		send_packet(icmp_timeout);
		free(icmp_timeout);
		return;
	}

	// get the destination ip
	dest_ip.s_addr = ip_header->daddr;

	// get the best route using the algorithm we wrote earlier

	// O(n) algorithm
	//struct route_table_entry* best_route = get_best_route(dest_ip, rtable, rtable_length);

	// search using trie
	struct route_table_entry* best_route = SearchTrie(routing_trie, dest_ip);

	// if we haven't found any valid route we drop the packet
	if(best_route == NULL){
		// crete host unreacheable icmp packet and send it
		packet *icmp_dest_unreach = create_icmp_packet(ICMP_DEST_UNREACH, *pckt);
		send_packet(icmp_dest_unreach);
		free(icmp_dest_unreach);
		return;
	}
	
	// gets the mac address of the next hop
	struct arp_entry* next_hop = get_next_hop(best_route->next_hop, arp_table, arp_table_length);
	// if we haven't found the entry in the cache
	if(next_hop == NULL){
		// create arp request and add the packet to the queue
		packet * arp_request = create_arp_request(best_route->next_hop, best_route->interface);
		send_packet(arp_request);
		free(arp_request); // free the memory for the packet created

		packet *pckt_to_add = (packet *) malloc(sizeof(packet));
		memcpy(pckt_to_add, pckt, sizeof(packet));
		queue_enq(pckt_queue, (void *) pckt_to_add);
		
	}
	else{
		update_and_send(pckt, ip_header, eth_header, best_route, next_hop);
	}
}

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

	// initialise trie and queue
	TrieNodePointer routing_trie = create_routing_trie(rtable, rtable_length);
	queue pckt_queue = queue_create();

	// create a dynamic arp table (stored in RAM)
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100);
	int arp_table_length = 0;
	

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// The code for basic forwarding will be very similar to the one given for lab4
		struct ether_header *eth_header = (struct ether_header *) m.payload;

		// retrieve router mac
		uint8_t router_mac[ETH_ALEN];
		get_interface_mac(m.interface, router_mac);

		// retrieve router address
		char *char_router_address;
		char_router_address = get_interface_ip(m.interface);
		uint32_t router_address;
		int code = inet_pton(AF_INET, char_router_address, &router_address);
		if(code != 1)
			printf("Error while converting address");

		// check if the packet recieved is if type Ethertype_IPV4
		if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){

			struct iphdr *ip_header = (struct iphdr *) (m.payload + sizeof(struct ether_header));

			// if we also have an icmp protocol stacked on top of the ip header
			if(ip_header->protocol == IPPROTO_ICMP){

				// extract icmp header
				struct icmphdr *icmp_header = (struct icmphdr *) (m.payload
									 + sizeof(struct ether_header) + sizeof(struct iphdr));
				
				// if the packet is of type echo and was sent to us (the router)
				if((icmp_header->type == ICMP_ECHO) && ip_header->daddr == router_address){

					// create icmp reply packet, send it and free the memory
					packet *echo_reply = create_icmp_packet(ICMP_ECHOREPLY, m);
					send_packet(echo_reply);
					free(echo_reply);
					continue;;
				}
			}
			// if is only ipv4 we'll do basic forwarding
			forward_ipv4_packet(&m, routing_trie, arp_table, arp_table_length, pckt_queue, eth_header);
		}
		// packet is of type arp
		else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
			// extract the arp header
			struct arp_header *arp_h = (struct arp_header *) (m.payload + sizeof(struct ether_header));

			// if it is arp request we need to reply
			if(ntohs(arp_h->op) == 1){
				packet *arp_reply = create_arp_reply(m);
				send_packet(arp_reply);
				free(arp_reply); // free the memory allocated for the packet
				continue;
			}
			
			// set the entry in our table
			arp_table[arp_table_length].ip = arp_h->spa;

			for(int i =0 ; i< 6 ; ++i){
				arp_table[arp_table_length].mac[i] = arp_h->sha[i];
			}

			// increment the size
			arp_table_length++;
			
			// as long as the queue is not empty
			queue new_queue = queue_create();
			while(!queue_empty(pckt_queue))
			{
				struct iphdr *ip_header;
				struct in_addr dest_ip;
				// extract packet and try to forward it
				packet *curr_packet = (packet *) queue_deq(pckt_queue);
				ip_header = (struct iphdr *) (curr_packet->payload + sizeof(struct ether_header));
				dest_ip.s_addr = ip_header->daddr;

				struct route_table_entry* best_route = SearchTrie(routing_trie, dest_ip);
				if(best_route == NULL)
					continue;

				struct arp_entry* next_hop = get_next_hop(best_route->next_hop, arp_table, arp_table_length);
				// if still no luck, enque it again and try later
				if(next_hop == NULL){
					queue_enq(new_queue, (void *) curr_packet);
					continue;
				}
				update_and_send(curr_packet, ip_header, eth_header, best_route, next_hop);
			}
			
			if(!queue_empty(new_queue))
				pckt_queue = new_queue;
		}

	}
}
