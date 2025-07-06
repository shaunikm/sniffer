#include <chrono>
#include <iostream>

extern "C" {
#include <pcap.h>
}

int main() {
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_if_t *all_devs;

  if (pcap_findalldevs(&all_devs, errbuf) == -1) {
    std::cerr << "Couldn't find devices :(" << std::endl;
    return 1;
  }

  const char *dev = all_devs->name;
  std::cout << "Device: " << dev << std::endl;

  pcap_freealldevs(all_devs);
}
