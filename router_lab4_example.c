#include "skel.h"

int interfaces[ROUTER_NUM_INTERFACES];

struct rtable_entry *rtable;
int rtable_len;

struct nei_entry *nei_table;
int nei_table_len;

int in6_cmp(struct in6_addr a, struct in6_addr b) {
    for (int i = 0; i < 16; i++) {
        if (a.s6_addr[i] < b.s6_addr[i])
		return -1;

        if (a.s6_addr[i] > b.s6_addr[i])
		return 1;
    }

    return 0;
}

struct in6_addr in6_mask(struct in6_addr a, struct in6_addr m) {
    struct in6_addr ret;

    for (int i = 0; i < 16; i++)
        ret.s6_addr[i] = a.s6_addr[i] & m.s6_addr[i];

    return ret;
}

/*
 Returns a pointer (eg. &rtable[i]) to the best matching route
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct rtable_entry *get_best_route(uint16_t proto, struct in_addr dest_ip, struct in6_addr dest_ip6) {
    size_t idx = -1;	

	// go through every entry of the routing table
    for (size_t i = 0; i < rtable_len; i++) {
		// if protocol is ipv4 and the current entry is also an ipv4 entry
        if ((proto == 4) && (rtable[i].proto == 4) &&
				// checks if the entry matches the destination ip using the AND operation on the mask
			 ((dest_ip.s_addr & rtable[i].netmask.s_addr) == rtable[i].network.s_addr)) {
				 // if it is the first time we set the ip
	    	if (idx == -1)
				idx = i;
				// checks if we can find a better prefix
				// we first have to convert from network order to host byte order
				// in order to do comparisons on our little endian machine
				// the bigger the netmask -> the more accurate
	    	else if (ntohl(rtable[idx].netmask.s_addr) < ntohl(rtable[i].netmask.s_addr))
				idx = i;
				// if the netmasks are equal but one has a better metric than the other (is faster)
				// then we also change
	    	else if ((rtable[idx].netmask.s_addr == rtable[i].netmask.s_addr) && (rtable[idx].metric > rtable[i].metric))
				idx = i;
		}

		// for the emoment we don't look at ipv6
		// is the same as before only this time we use in6_cmp function to compare the addresses
        if ((proto == 6) && (rtable[i].proto == 6) && (in6_cmp(in6_mask(dest_ip6, rtable[i].netmask6), rtable[i].network6) == 0)) {
	    if (idx == -1) idx = i;
	    else if (in6_cmp(rtable[idx].netmask6, rtable[i].netmask6) < 0) idx = i;
	    else if ((in6_cmp(rtable[idx].netmask6, rtable[i].netmask6) == 0) && (rtable[idx].metric > rtable[i].metric)) idx = i;
	}
    }
    
	// if we haven't found an entry
    if (idx == -1)
        return NULL;

	// otherwise we return a pointer to that specific entry
    else
        return &rtable[idx];
}


// a neighbour table maps an ip to a mac address
/*
 Returns a pointer (eg. &nei_table[i]) to the best matching neighbor table entry.
 for the given protocol and destination address. Or NULL if there is no matching route.
*/
struct nei_entry *get_nei_entry(uint16_t proto, struct in_addr dest_ip, struct in6_addr dest_ip6) {

	// iterates through each entry
    for (size_t i = 0; i < nei_table_len; i++) {
		// checks the protocol
        if ((nei_table[i].proto == 4) && (proto == 4)
			// compares the bytes 
			// could have used ==
			&& (memcmp(&dest_ip, &nei_table[i].ip, sizeof(struct in_addr)) == 0))
	    return &nei_table[i];

        if ((nei_table[i].proto == 6) && (proto == 6) && (memcmp(&dest_ip6, &nei_table[i].ip6, sizeof(struct in6_addr)) == 0))
	    return &nei_table[i];
    }

    return NULL;
}

int main(int argc, char *argv[])
{
	msg m;
	int rc;

	init();
	rtable = malloc(sizeof(struct rtable_entry) * 100);
	DIE(rtable == NULL, "memory");

	nei_table = malloc(sizeof(struct  nei_entry) * 100);
	DIE(nei_table == NULL, "memory");

	rtable_len = read_rtable(rtable);
	nei_table_len = read_nei_table(nei_table);
	/* Students will write code here */

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_message");

		// eth header struct
		struct ether_header *eth = (struct ether_header *) m.payload;

		// ip header and ipv6 header
		struct iphdr *iph;
		struct ip6_hdr *ip6h;

		// destination ip stored in in_addr for ipv4
		struct in_addr dest_ip;
		struct in6_addr dest_ip6;
		uint16_t proto;

		// checks if the ether type is 2048 (0x0800) (Ethertype_IPV4)
		if (ntohs(eth->ether_type) == 0x0800) {

			// extract the ip header
			iph = ((void *) eth) + sizeof(struct ether_header);
			/*
			Could have used
			iph = (struct iphdr *) (m.payload + sizeof(struct ether_header))

			*/
			
			// if the checksum of the ip header is not 0 then we drop the packet
			if (ip_checksum((void *) iph, sizeof(struct iphdr)) != 0)
				continue;

			// if the time to live got to 0 then we also drop the packet
			if (iph->ttl == 0)
				continue;

			// get the destination ip from the ip header
			dest_ip.s_addr = iph->daddr;
			proto = 4;
		}
		
		// same thing just for ipv6
		if (ntohs(eth->ether_type) == 0x86DD) {
			ip6h = ((void *) eth) + sizeof(struct ether_header);

			if (ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim == 0)
				continue;

			dest_ip6 = ip6h->ip6_dst;
			proto = 6;
		}

		// get the best route using the algorithm we wrote earlier
		struct rtable_entry *route = get_best_route(proto, dest_ip, dest_ip6);

		// if we haven't found a route we drop the packet
		if (route == NULL)
			continue;

		// gets the mac address of the next hope
		struct nei_entry *nei = get_nei_entry(proto, route->nexthop, route->nexthop6);

		// if we haven't found the entry
		if (nei == NULL)
			continue;

		// ipv4
		if (proto == 4) {
			// decrement tie to live
			iph->ttl--;
			// set the checksum to 0
			iph->check = 0;
			// calculate the checksum again
			iph->check = ip_checksum((void *) iph, sizeof(struct iphdr));
		}

		if (proto == 6)
			ip6h->ip6_ctlun.ip6_un1.ip6_un1_hlim--;

		// put in the ethernet header the new destionation mac
		// it has 6 bytes
		memcpy(eth->ether_dhost, nei->mac, 6);

		// get the mac address of the source (i.e the interface from which we will send the packet)
		// set it in the ethernet header before sending it
		get_interface_mac(route->interface, eth->ether_shost);

		// sending the packet on the specified interface
		send_packet(route->interface, &m);
	}
}
