//
// Created by Shaunik Musukula on 7/6/25.
//

#ifndef NETDEV_LOOKUP_H
#define NETDEV_LOOKUP_H

#include <string>
#include <map>
#include <pcap/pcap.h>

struct DeviceMapping {
    pcap_if_t* iface{};
    std::string description;
};

DeviceMapping match_iface_pcap(pcap_if_t* iface);

#endif //NETDEV_LOOKUP_H
