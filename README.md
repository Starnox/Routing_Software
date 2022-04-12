#### Communication Protocols
## Student: Mihailescu Eduard-Florin 

### Overview
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

`main` -> begin initialising objects in memory: 
    - routing table (taken as an argument) as a `route_table_entry*`
    - dynamic arp table (this will be updated on the go)
    - routing trie (precalculations for our trie)
       -> afterwards the program stays in a loop and "listens" for packets.
       When we recieve a packet, we extract the ethernet header and then check it's type,
       and depending on that type  we do different things
       