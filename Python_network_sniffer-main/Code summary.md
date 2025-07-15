This code functions as a packet analyzer, capturing and processing incoming network packets using the `socket` library, with support for multiple protocols such as Ethernet, IPv4, ICMP, TCP, UDP, and HTTP. Here’s a brief breakdown of each main step:

1. **Program Initialization**: Sets up symbols for displaying data in a hierarchical format and opens a `pcap` file to store captured packets.

2. **Socket Setup**: Creates a RAW socket of type `AF_INET` to capture network packets at the IP layer and configures it to accept packets with full IP headers.

3. **Packet Reception**: Enters an infinite loop to continuously receive packets from the network, storing each packet directly into the `pcap` file.

4. **Ethernet Parsing**: Parses the initial frame as an Ethernet frame, displaying source and destination MAC addresses and the protocol type.

5. **IP Protocol Handling**: If the packet is IPv4, it processes and displays details like the IP version, header length, TTL, source, and destination addresses. Based on the encapsulated protocol within IPv4, it does the following:
    - **ICMP**: Shows ICMP type, code, and checksum.
    - **TCP**: Displays TCP information such as source and destination ports, sequence, and acknowledgment numbers. If port 80 (HTTP) is detected, it further parses the data as HTTP.
    - **UDP**: Shows source and destination ports and the packet length.

6. **Unknown Packets**: If the packet is not IPv4, it displays the data as a general Ethernet frame.

7. **Closing the File**: Closes the `pcap` file once packet reception is finished.
