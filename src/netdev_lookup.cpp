//
// Created by Shaunik Musukula on 7/6/25.
//

#include "netdev_lookup.h"

std::map<std::string, std::string> get_interface_descriptions() {
    std::map<std::string, std::string> mapping;
    FILE* fp = popen("networksetup -listallhardwareports", "r");
    if (!fp) return mapping;

    char line[256];
    std::string port;

    while (fgets(line, sizeof(line), fp)) {
        if (std::string str(line); str.find("Hardware Port:") == 0) {
            port = str.substr(15);
            port.erase(port.find_last_not_of(" \n\r\t") + 1);
        } else if (str.find("Device:") == 0) {
            std::string device = str.substr(8);
            device.erase(device.find_last_not_of(" \n\r\t") + 1);
            mapping[device] = port;
        }
    }

    pclose(fp);
    return mapping;
}

static std::string get_known_interface_description(const std::string& name) {
    // MacOS Interface Names
    // Sourced from: https://www.chilkatsoft.com/MacOS_Network_Interface_Names.asp
    if (name == "lo0")          return "Loopback Interface";
    if (name == "awdl0")        return "Apple Wireless Direct Link";
    if (name == "llw0")         return "Low-Latency WAN";
    if (name == "bridge0")      return "Bridge Interface";
    if (name == "stf0")         return "6to4 Tunnel";
    if (name == "ap1")          return "Access Point";

    if (name.rfind("gif", 0) == 0)      return "Generic Tunnel";
    if (name.rfind("p2p", 0) == 0)      return "Peer-to-Peer";
    if (name.rfind("en", 0) == 0)       return "Wi-Fi/Ethernet";
    if (name.rfind("utun", 0) == 0)     return "User Tunneling";
    if (name.rfind("anpi", 0) == 0)     return "Apple Network Protocol";
    if (name.rfind("vmenet", 0) == 0)   return "VM Network";

    return "No description";
}

const std::map<std::string, std::string>& get_cached_device_descriptions() {
    static const std::map<std::string, std::string> cached = get_interface_descriptions();
    return cached;
}

DeviceMapping match_iface_pcap(pcap_if_t* iface) {
    const auto& dev_desc = get_cached_device_descriptions();
    const auto it = dev_desc.find(std::string(iface->name));

    DeviceMapping dev;
    dev.iface = iface;
    const std::string name = iface->name;

    if (it != dev_desc.end()) {
        dev.description = it->second;
    } else {
        dev.description = get_known_interface_description(name);
    }

    return dev;
}