//
// Created by Shaunik Musukula on 7/6/25.
//

#include "netdev_lookup.h"

std::map<std::string, std::string> get_device_descriptions() {
    std::map<std::string, std::string> mapping;
    FILE* fp = popen("networksetup -listallhardwareports", "r");
    if (!fp) return mapping;

    char line[256];
    std::string port;

    while (fgets(line, sizeof(line), fp)) {
        std::string str(line);
        if (str.find("Hardware Port:") == 0) {
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

const std::map<std::string, std::string>& get_cached_device_descriptions() {
    static const std::map<std::string, std::string> cached = get_device_descriptions();
    return cached;
}

DeviceMapping match_iface_pcap(pcap_if_t* iface) {
    const auto& dev_desc = get_cached_device_descriptions();
    const auto it = dev_desc.find(std::string(iface->name));

    DeviceMapping dev;
    dev.iface = iface;
    dev.description = (it != dev_desc.end() ? it->second : "(No description)");
    return dev;
}
