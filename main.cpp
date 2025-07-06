#include <iostream>
#include <chrono>
#include <stdlib.h>

extern "C" {
    #include <pcap/pcap.h>
}

void throw_error(const char* msg) {
    std::cerr << msg << std::endl;
    exit(EXIT_FAILURE);
}

void get_devices(pcap_if_t** devs, char* errbuf) {
    if (pcap_findalldevs(devs, errbuf) == -1) {
        std::cerr << "Interface not found:" << std::endl;
        throw_error(errbuf);
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *all_devs = nullptr;
    pcap_t *handle = nullptr;

    get_devices(&all_devs, errbuf);
    const char* dev = all_devs->name;

    handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Couldn't open device:" << std::endl;
        throw_error(errbuf);
    }

    std::cout << "Device: " << dev << std::endl;

    pcap_freealldevs(all_devs);
}
