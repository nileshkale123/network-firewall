# network-firewall

We put in place a straightforward network firewall with two network interface cards connecting to the internal network we intended to safeguard and the external network (Internet). On top of the firewall created, the supported rule set was extended to include MAC, IPv4/IPv6, ICMP for IPv4/v6, and TCP/UDP. It filters traffic for all mentioned tiers before deciding whether to forward the packet on or not.

Additionally identified a DOS attack with a specified limit.

With the help of the NPING traffic generator tool, we created our own script to generate random traffic.
