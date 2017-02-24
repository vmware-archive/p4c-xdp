# p4c-xdp test cases

## xdp1.p4 (basic parser)
- Parse:
  L2(Ethernet) and L3 (IPv4) 
- Action:
  Drop if not IP packet (the ARP will be dropped)
- Deparse:
  None

## xdp2.p4 (parser + deparser)
- Parse:
  L2, L3 (IPv4), L4 (icmp)
- Action:
  Drop if not IP packet (the ARP will be dropped)
- Deparse:
  L2, L3 (IPv4), L4 (icmp)

## xdp3.p4 (parser + lookup + deparser)
- Parse:
  L2, L3 (IPv4)
- Table:
  Ethernet.destination as key, action could be drop or pass
```C
    table dstmactable() {
        key = { hdr.ethernet.destination : exact; }
        actions = { 
            Fallback_action;
            Drop_action;
        }
```
- Deparse:
  L2, L3 (IPv4)

## xdp4.p4 (parser + lookup with multiple fields as key + deparser)
- Parse:
  L2, L3 (IPv4)
- Table:
  Ethernet.{destination, protocl} as key, action could be drop or pass 
```C
    table dstmactable() {
        key = { hdr.ethernet.destination : exact;
		hdr.ethernet.protocol: exact;}
```
- Deparse:
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
- Parse:
  L2, L3 (IPv4)
- Table:
```C
    action SetTTL_action(action_md_t md) 
    {   
        hd.ipv4.ttl = md.ttl;
        xout.output_action = xdp_action.XDP_PASS;
    }   
```
- Deparse:
  L2, L3 (IPv4)

## xdp7.p4 and xdp8.p4 
Internal use for debugging

## xdp9.p4 (ipv4 checksum recalc)
- Parse:
  L2, L3 (IPv4), L4 (TCP, UDP, ICMP)
- Table:

```C
    action Fallback_action()
    {   
        hd.ipv4.ttl = 4;
        hd.ipv4.hdrChecksum = ebpf_ipv4_checksum(
                            hd.ipv4.version, hd.ipv4.ihl, hd.ipv4.diffserv,
```
- Deparse:
  L2, L3

## xdp10.p4 (Counter)
Count the number of received ipv4 packets for a particular
IPv4 destination address.  A BPF hashmap is created for key
equals ipv4.dstAddr, value equals u32 counter.
```C
    apply {
        if (hd.ipv4.isValid())
        {
            counters.increment((bit<32>)hd.ipv4.dstAddr);
        }
```
Compile the user\_xdp10.c and it will dump the counter

## xdp11.p4 (Swap ethernet src and dst, then XDP\_TX)
Try to do similar feature as kernel's samples/bpf/xdp2\_kern.c
```C
    bit<48> tmp;
    apply {
        if (hd.ipv4.isValid())
        {
            tmp = hd.ethernet.destination;
            hd.ethernet.destination = hd.ethernet.source;
            hd.ethernet.source = tmp;
        }
```
## xdp12.p4
- Parse IPv4/IPv6 ping
- Update ipv4 statistics, and return XDP\_PASS
- Drop ipv6 ping, and return XDP\_DROP

## xdp13.p4 (Multiple Tables, Single Action)
- Parse L2, L3, L4 (icmp)
- Create and lookup L2, L3, L4 tables
- Default will drop ipv4 ICMP
- XDP\_PASS for the rest of the traffic

## xdp14.p4 (Multiple Actions, Single Table)
- Parse L2, L3, L4 (icmp)
- Create 1 table with value = bitmap of actions to execute

## xdp15.p4 (Encapsulation)
- unconditionally append a fixed customized header in front of Ethernet header
```C
/* encap my own header */
header myhdr_t {
    bit<32> id; 
    bit<32> timestamp;
}
```
then at deparser, emit it before ethernet header
```C
control Deparser(in Headers hdrs, packet_out packet) {
    apply {
        packet.emit(hdrs.myhdr);
        packet.emit(hdrs.ethernet);
    }   
}
```
## xdp16.p4 (BPF XDP helpers)
## TODO

