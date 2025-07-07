//
// Created by Shaunik Musukula on 7/6/25.
//

#pragma once

#include <string>
#include <map>
#include <pcap/pcap.h>

struct DeviceMapping {
    pcap_if_t* iface{};
    std::string description;
};

DeviceMapping match_iface_pcap(pcap_if_t* iface);
