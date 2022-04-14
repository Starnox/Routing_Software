# Communication Protocols
### Student: Mihailescu Eduard-Florin 

## Overview
This code is meant to solve a challenge given by the Communication Protocols team
as part of the curriculum studying at Faculty of Automatic Control and Computers 
in Bucharest. I implemented and tested a functioning network with 2 routers and 4
hosts with the help of mininet. I wrote code for the forwarding of packets using
an efficient LPM algorithm that works with a Trie, also implemented the arp and
icmp protocol. I mention that my solution recieved locally a maximum score (110/110).
The bonus (checksum incremental update) was completed with a formula found on the following
website: https://www.rfc-editor.org/rfc/pdfrfc/rfc1141.txt.pdf

### router.c
The bulk of the code was written in this file. This is the startpoint of the program
that will run on the routers. 

```c
int main(int argc, char *argv[])
```
- Begin initialising objects in memory: 
    - routing table (taken as an argument) as a `route_table_entry*`
    - dynamic arp table (this will be updated on the go)
    - routing trie (precalculations for our trie)
       -> afterwards the program stays in a loop and "listens" for packets.
       When we recieve a packet, we extract the ethernet header and then check it's type,
       and depending on that type we do different things:

-   If the packet has an ip header then we either look for
and additional icmp header which contain an ECHO Request for
the router, in which case we create an ECHO Reply with 
`create_icmp_packet(ICMP_ECHOREPLY,m)` and then send to
the host that originated the package, otherwise we call
`forward_ipv4_packet()` which will direct the packet to the
correct route.

-   If the packet has an arp header, then we first check the op
type: For an arp request, we create an arp reply with
`create_arp_reply()` and send it. For and arp reply
we update the internal arp table and go through the queue of
packets left to send and try to send them again having the
updated table.

---
```c
struct route_table_entry *get_best_route(struct in_addr dest_ip, 
        struct route_table_entry *rtable, int rtable_len)
```
 -  this function is
not used in the program and is just kept as a backup. In works in
O(n) time by going over each entry in the routing table and finding
the most specific route

```c
struct arp_entry* get_next_hop(uint32_t dest_ip, struct arp_entry* arp_table, int arp_table_length){
```
- gets the MAC address of a
specific IP or NULL if it doesn't exist in the table

```c
packet *create_arp_reply(packet m)
```
-  complete the necessary
information in the ethernet (source and destination mac, type)
 and arp (type, length, op, target ip/mac etc) headers,
allocate the memory and return the package

```c
packet create_arp_request(uint32_t dest_ip, int interface)s
```
- complete the necessary
information in the ethernet and arp headers, allocate the
memory and return the package

```c
packet *create_icmp_packet(int type_of_packet, packet m)
```
- complete the necessary
information in the ethernet and ipv4 and icmp headers, 
allocate the memory and return the package

```c
TrieNodePointer create_routing_trie(struct route_table_entry *rtable, int rtable_len){
```

- recieve the routing trie as a parameter (rtable)
- go through each entry and add it to the trie with `InsertNode()`

```c
void update_and_send(packet *m, struct iphdr *ip_header,struct ether_header *eth_header,
				struct route_table_entry *best_route, struct arp_entry* next_hop ){
```