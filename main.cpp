#include "netdev_lookup.h"
#include "net_types.h"

#include <iostream>
#include <map>
#include <cstdio>
extern "C" {
    #include <pcap/pcap.h>
}

void throw_error(const char* msg) {
    std::cerr << msg << std::endl;
    exit(EXIT_FAILURE);
}

void def_device(pcap_if_t** iface, char* errbuf) {
    if (pcap_findalldevs(iface, errbuf) == PCAP_ERROR) {
        std::cerr << "Interface not found:" << std::endl;
        throw_error(errbuf);
    }
}

pcap_t* open_device(const DeviceMapping* dev_map, char* errbuf) {
    pcap_t* handle = pcap_open_live(dev_map->iface->name, BUFSIZ, PROMISCUOUS_MODE, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device:" << std::endl;
        throw_error(errbuf);
    }
    std::cout << "Opened device: " << dev_map->iface->name << " (" << dev_map->description << ")" << std::endl;
    return handle;
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_if_t* iface = nullptr;
    pcap_t* handle = nullptr;
    DeviceMapping dev{};

    bpf_u_int32 mask;
    bpf_u_int32 net;
    pcap_pkthdr header{};

    def_device(&iface, errbuf);
    dev = match_iface_pcap(iface);

    handle = open_device(&dev, errbuf);

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Device " << dev.iface->name << " doesn't provide Ethernet headers - not supported\n";
        return 1;
    }

    if (pcap_lookupnet(dev.iface->name, &net, &mask, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "Couldn't get netmask for device %s: %s\n", dev.iface->name, errbuf);
        net = 0;
        mask = 0;
    }

    handle = pcap_open_live(dev.iface->name, BUFSIZ, PROMISCUOUS_MODE, 1000, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "Couldn't open device %s: %s\n", dev.iface->name, errbuf);
        return 1;
    }

    const std::uint8_t *packet = pcap_next(handle, &header);
    std::cout << "Jacked a packet with length of [" << header.len << "B]\n";
    if (header.caplen == header.len) {
        std::cout << "Packet size was not truncated.\n";
    }

    const auto eth = reinterpret_cast<const ethernet_header *>(packet);

    const auto ip = reinterpret_cast<const ip_header *>(packet + SIZE_ETHERNET);
    const std::uint32_t size_ip = IP_HL(ip) * 4;

    if (size_ip < 20) {
        std::cout << "\t* Invalid IP header length: " << size_ip << " bytes\n";
    }

    const auto tcp = reinterpret_cast<const tcp_header*>(packet + SIZE_ETHERNET + size_ip);
    const std::uint32_t size_tcp = TH_OFF(tcp) * 4;

    if (size_tcp < 20) {
        std::cout << "\t* Invalid TCP header length: " << size_ip << " bytes\n";
    }

    const auto payload = packet + SIZE_ETHERNET + size_ip + size_tcp;
    const auto payload_len = header.len - size_ip - size_tcp;

    print_payload_hex(payload, payload_len);

    pcap_freealldevs(iface);
    pcap_close(handle);
    std::cout << "Closed session handler." << std::endl;

    return 0;
}
