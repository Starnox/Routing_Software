# Communication Protocols
### Student: Mihailescu Eduard-Florin 322CB

## Overview
This code is meant to solve a challenge given by the Communication Protocols team
as part of the curriculum studying at Faculty of Automatic Control and Computers 
in Bucharest. I implemented and tested a functioning network with 2 routers and 4
hosts with the help of mininet. I wrote code for the forwarding of packets using
an efficient LPM algorithm that works with a Trie, also implemented the arp and
icmp protocol. I mention that my solution recieved locally a maximum score (110/110).
The bonus (checksum incremental update) was completed with a formula found on the following
website: https://www.rfc-editor.org/rfc/pdfrfc/rfc1141.txt.pdf

---
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
 -  This function is
not used in the program and is just kept as a backup. In works in
O(n) time by going over each entry in the routing table and finding
the most specific route

```c
struct arp_entry* get_next_hop(uint32_t dest_ip, struct arp_entry* arp_table, int arp_table_length){
```
- Gets the MAC address of a
specific IP or NULL if it doesn't exist in the table

```c
packet *create_arp_reply(packet m)
```
-  Complete the necessary
information in the ethernet (source and destination mac, type)
 and arp (type, length, op, target ip/mac etc) headers,
allocate the memory and return the package

```c
packet create_arp_request(uint32_t dest_ip, int interface)s
```
- Complete the necessary
information in the ethernet and arp headers, allocate the
memory and return the package

```c
packet *create_icmp_packet(int type_of_packet, packet m)
```
- Complete the necessary
information in the ethernet and ipv4 and icmp headers, 
allocate the memory and return the package

```c
TrieNodePointer create_routing_trie(struct route_table_entry *rtable, int rtable_len){
```

- Recieve the routing trie as a parameter (rtable)
- Go through each entry and add it to the trie with `InsertNode()`

```c
void update_and_send(packet *m, struct iphdr *ip_header,struct ether_header *eth_header,
				struct route_table_entry *best_route, struct arp_entry* next_hop ){
```
- Decrease the packet time to live, recalculate checksum using rfc 1624, replace the destination
mac in the ethernet header with the new MAC, replace also the interface field and afterwards
send the packet using `send_packet()`

```c
void forward_ipv4_packet(packet *pckt, TrieNodePointer routing_trie, struct arp_entry *arp_table,
						int arp_table_length, queue pckt_queue, struct ether_header *eth_header){
```
- Extract the ip header 
- Verify the integrity of the package by checking the checksum (is should be 0)
- Verify time to live:
    -   If it less than or equal to 1 then we create an `ICMP_TIME_EXCEEDED`
packet with `create_icmp_packet` and we send it
    -   Otherwise we continue the function
- Search for the best route to send the package using a search on trie `SearchTrie()`.
    -   If there is no available route then an `ICMP_DEST_UNREACH` packet is created and sent
    -   Otherwise the function continues  
- Check if the ip of the route we need to take is in the routers arp table
    -   If yes, then `update_and_send()` is called
    -   Otherwise, an arp request is created and sent and the current packet is added in a queue
    for it to be sent when the arp reply returns
---
### trie.c

```c
TrieNodePointer InitialiseTrieNode()
```
-   Allocate memory for a new trie and set initial values to NULL

```c
int InsertNode(TrieNodePointer trieNode, struct route_table_entry *entry)
```
-   Gets a routing table entry, goes through every bit of the prefix and depending on
its value 0/1 create and connect a new trie node.

```c
struct route_table_entry* SearchTrie(TrieNodePointer node, struct in_addr addr)
```
- Similarly to `InsertNode`, goes through every bit of the address being searched and tries
to match as closely as possible to a route already constructed in the trie.
- When an address is found, is is retained and at the end, the last address found is returned.

```c
int IsEmpty(TrieNodePointer node)
```
- Checks if a trie node is empty or not
