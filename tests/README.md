# p4c-xdp test cases

## xdp1.p4 (basic parser)
Parse:
L2(Ethernet) and L3 (IPv4) 
Action:
Drop if not IP packet (the ARP will be dropped)
Deparse:
None

## xdp2.p4 (parser + deparser)
Parse:
L2, L3 (IPv4), L4 (icmp)
Action:
Drop if not IP packet (the ARP will be dropped)
Deparse:
L2, L3 (IPv4), L4 (icmp)

## xdp3.p4 (parser + lookup + deparser)
Parse:
L2, L3 (IPv4)
Table:
Ethernet.destination as key, action could be drop or pass
```C
    table dstmactable() {
        key = { hdr.ethernet.destination : exact; }
        actions = { 
            Fallback_action;
            Drop_action;
        }
```
Deparse:
L2, L3 (IPv4)

## xdp4.p4 (parser + lookup with multiple fields as key + deparser)
Parse:
L2, L3 (IPv4)
Table:
Ethernet.{destination, protocl} as key, action could be drop or pass 
```C
    table dstmactable() {
        key = { hdr.ethernet.destination : exact;
		hdr.ethernet.protocol: exact;}
```
Deparse:
L2, L3 (IPv4)

## xdp5.p4 (Test control plane)
Test using user\_xdp5.c
```bash
# gcc -I ../lib/ ../lib/libbpf.o user_xdp5.c -o xdp5 
# ./xdp5
```
The function "initialize\_tables()" will set default to drop the packet.
Then we populate the table by allowing the IP packet to execute Fallback\_action

## xdp6.p4 (Add action metadata to set IP ttl)
Parse:
L2, L3 (IPv4)
Table:
```C
    action SetTTL_action(action_md_t md) 
    {   
        hd.ipv4.ttl = md.ttl;
        xout.output_action = xdp_action.XDP_PASS;
    }   
```
Deparse:
L2, L3 (IPv4)

## xdp7.p4
## xdp8.p4


## TODO
