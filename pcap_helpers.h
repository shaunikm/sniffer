//
// Created by Shaunik Musukula on 7/7/25.
//

#pragma once

#include <cstdint>
#include <cstdio>

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>

#ifdef __cplusplus
}
#endif

void open_device(std::size_t idx);

void maintain_selection();

void packet_cb(std::uint8_t* user, const pcap_pkthdr* h, const std::uint8_t* pkt);