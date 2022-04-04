#include "queue.h"
#include "skel.h"


struct route_table_entry *get_best_route(struct in_addr dest_ip, struct route_table_entry *rtable, int rtable_len) {
    size_t idx = -1;	

	// go through every entry of the routing table
    for (size_t i = 0; i < rtable_len; i++) {
		// if protocol is ipv4 and the current entry is also an ipv4 entry
        if (((rtable[i].proto == 4) &&
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
    }
    
	// if we haven't found an entry
    if (idx == -1)
        return NULL;

	// otherwise we return a pointer to that specific entry
    else
        return &rtable[idx];
}


int main(int argc, char *argv[])
{
	packet m;
	int rc;

	// Do not modify this line
	init(argc - 2, argv + 2);

	while (1) {
		rc = get_packet(&m);
		DIE(rc < 0, "get_packet");
		/* TODO */


	}
}
