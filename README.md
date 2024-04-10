# Networking-Protocols-Implementation
Implementation of various networking protocols in C

# 1. ARP:
The Address Resolution Protocol (ARP) is a communication protocol that connects a dynamic IP address to a fixed physical machine address, also known as a media access control (MAC) address. ARP is essential to routing traffic to the correct computer within a subnet.ARP works by translating 32-bit IP addresses to 48-bit MAC addresses, and vice versa. For example, when a new computer joins a local area network (LAN), the network assigns it a unique IP address.
Here, we develop ARP (Address Resolution Protocol) functionalities as a user space application, we will call that as ARP-App. In reality, ARP acts as a module in Network Layer as part of the Kernel (TCP/IP stack).


