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

// creates and returns an arp request packet for the specified ip
packet* create_arp_request(uint32_t dest_ip, int interface){
	// initialise a new packet
	packet *new_packet = (packet *) malloc(sizeof(packet));
	// add the interface to the packet
	new_packet->interface = interface;

	// set FF:FF:FF:FF:FF:FF as the destionation mac (broadcast)
	struct ether_header *eth_header =  (struct ether_header *) malloc(sizeof(struct ether_header));
	memcpy(eth_header->ether_dhost, ether_broadcast, sizeof(ether_broadcast));
	
	// get the router mac address
	uint8_t router_mac[ETH_ALEN];
	get_interface_mac(interface, router_mac);

	// set the the source mac address
	memcpy(eth_header->ether_shost, router_mac, sizeof(router_mac));

	// set ether type
	eth_header->ether_type = ETHERTYPE_ARP;

	// add the frame to the packet
	memcpy(new_packet, eth_header, sizeof(struct ether_header));

	// TODO create an arp frame
	struct arp_header *arp_h = (struct arp_header *) malloc(sizeof(struct arp_header));

	arp_h->htype = 1;
	arp_h->ptype = ETHERTYPE_IP;
	arp_h->hlen = 6;
	arp_h->plen = 4;
	arp_h->op = 1;
	memcpy(arp_h->sha, router_mac, sizeof(router_mac));

	char * char_router_address = get_interface_ip(interface);
	uint32_t router_address;
	int code = inet_pton(AF_INET, char_router_address, &router_address);
	if(code != 1)
		printf("Error while converting address");

		
	arp_h->spa = router_address;
	memset(arp_h->tha, 0, sizeof(router_mac));
	arp_h->tpa = dest_ip;

	memcpy(new_packet + sizeof(struct ether_header), arp_h, sizeof(struct arp_header));

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
	m->interface = best_route->interface;

	// sending the packet on the specified interface
	send_packet(m);
}


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
	if(ip_header->ttl == 0)
		return;

	// get the destination ip
	dest_ip.s_addr = ip_header->daddr;

	// get the best route using the algorithm we wrote earlier

	// O(n) algorithm
	//struct route_table_entry* best_route = get_best_route(dest_ip, rtable, rtable_length);

	// search using trie
	struct route_table_entry* best_route = SearchTrie(routing_trie, dest_ip);

	// if we haven't found any valid route we drop the packet
	if(best_route == NULL)
		return;
	
	// gets the mac address of the next hop
	struct arp_entry* next_hop = get_next_hop(best_route->next_hop, arp_table, arp_table_length);
	// if we haven't found the entry in the cache
	if(next_hop == NULL){
		// create arp request and add the packet to the queue
		packet * arp_request = create_arp_request(best_route->next_hop, best_route->interface);
		send_packet(arp_request);
		queue_enq(pckt_queue, (void *) pckt);
	}
	else{
		update_and_send(pckt, ip_header, eth_header, best_route, next_hop);
	}
}

int main(int argc, char *argv[])
{
	packet m;
	int rc;

	uint8_t ether_broadcast[ETH_ALEN];
	for(int i = 0; i< ETH_ALEN; ++i)
		ether_broadcast[i] = 0xff;

	// Do not modify this line
	init(argc - 2, argv + 2);


	// extract the routing table from the argument list -> argv[1]
	char *routing_table_location = argv[1];

	// declare and initialise the routing table
	struct route_table_entry* rtable = malloc(sizeof(struct route_table_entry) * MAX_NUM_ADDRESSES);
	int rtable_length = read_rtable(routing_table_location, rtable);

	// initialise trie
	TrieNodePointer routing_trie = create_routing_trie(rtable, rtable_length);

	// TODO Delete this test
	/*
	char *testAddress = "192.73.207.90";
	struct in_addr test_addr;
	inet_aton(testAddress, &test_addr);
	
	struct route_table_entry *test = SearchTrie(routing_trie, test_addr);
	if(test == NULL)
		printf("NULL\n");
	test_addr.s_addr = test->prefix;
	printf("%s\n", inet_ntoa(test_addr));
	*/
	
	// declare and initialise the arp table

	// this is for the one already given
	
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100);
	int arp_table_length = parse_arp_table(ARP_TABLE_LOCATION, arp_table);
	

	queue pckt_queue = queue_create();

	// create a dynamic arp table

	/*
	struct arp_entry *arp_table = malloc(sizeof(struct arp_entry) * 100);
	int arp_table_length = 0;
	*/

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");

		// The code for basic forwarding will be very similar to the one given for lab4

	
		struct ether_header *eth_header = (struct ether_header *) m.payload;

		// declare the ip header and destination ip
		

		// TODO check if the packet is malformed
		//get_interface_mac(best_route->interface, eth_header->ether_shost);
		uint8_t router_mac[ETH_ALEN];
		get_interface_mac(m.interface, router_mac);

		/*
		for(int i =0 ; i< 6 ; ++i){
			printf("%02x:", eth_header->ether_dhost[i]);
		}
		printf("\n");
		for(int i =0 ; i< 6 ; ++i){
			printf("%02x:", router_mac[i]);
		}
		printf("\n\n");
		*/

		// TODO L2 validation -> check if this packet destination is this router
		// or broadcast

		/*
		if((memcmp(eth_header->ether_dhost, router_mac, sizeof(router_mac)) != 0 )
				&& (memcmp(eth_header->ether_dhost, ether_broadcast, sizeof(ether_broadcast)) != 0 ))
				continue;
		*/


		// check if the packet recieved is if type Ethertype_IPV4

		
		if(ntohs(eth_header->ether_type) == ETHERTYPE_IP){
			forward_ipv4_packet(&m, routing_trie, arp_table, arp_table_length, pckt_queue, eth_header);
		}
		// packet is of type arp
		// else if(ntohs(eth_header->ether_type) == ETHERTYPE_ARP){
		// 	// extract the arp header
		// 	struct arp_header *arp_h = (struct arp_header *) (m.payload + sizeof(struct arp_header));

		// 	// if it is arp request we need to forward it
		// 	if(arp_h->op == 1)
		// 		continue;
			
		// 	// set the entry in our table
		// 	arp_table[arp_table_length].ip = arp_h->spa;
		// 	memcpy(arp_table + arp_table_length, arp_h->sha, 6);
		// 	// increment the size
		// 	arp_table_length++;

		// 	// as long as the queue is not empty
		// 	while(!queue_empty(pckt_queue))
		// 	{
		// 		// extract packet and check if we have it mapped in our cache
		// 		packet *curr_packet = (packet *) queue_deq(pckt_queue);
		// 		forward_ipv4_packet(curr_packet, routing_trie, arp_table, arp_table_length, pckt_queue, eth_header);

		// 	}
		// }

	}
}
