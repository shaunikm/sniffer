//
// Created by Shaunik Musukula on 7/6/25.
//

#pragma once

#include <string>
#include <map>

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>

#ifdef __cplusplus
}
#endif

struct DeviceMapping {
    pcap_if_t* iface{};
    std::string description;
};

DeviceMapping match_iface_pcap(pcap_if_t* iface);
