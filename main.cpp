#include "netdev_lookup.h"

#include <iostream>
#include <map>
#include <cstdio>
extern "C" {
    #include <pcap/pcap.h>
}

constexpr int PROMISCUOUS_MODE = 1;

void throw_error(const char* msg) {
    std::cerr << msg << std::endl;
    exit(EXIT_FAILURE);
}

void get_devices(pcap_if_t** iface, char* errbuf) {
    if (pcap_findalldevs(iface, errbuf) == -1) {
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

    get_devices(&iface, errbuf);
    dev = match_iface_pcap(iface);

    handle = open_device(&dev, errbuf);

    if (pcap_datalink(handle) != DLT_EN10MB) {
        std::cerr << "Device " << dev.iface->name << " doesn't provide Ethernet headers - not supported" << std::endl;
        return(2);
    }

    pcap_freealldevs(iface);
    pcap_close(handle);
    std::cout << "Closed session handler." << std::endl;
}
