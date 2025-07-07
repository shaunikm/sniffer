//
// Created by Shaunik Musukula on 7/6/25.
//

#pragma once

#include <cstdint>

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>

#ifdef __cplusplus
}
#endif

constexpr size_t ETHER_ADDR_LEN = 6;
constexpr int PROMISCUOUS_MODE = 1;

#pragma pack(push, 1)

struct ethernet_header {
    std::uint8_t    dst_mac[ETHER_ADDR_LEN];
    std::uint8_t    src_mac[ETHER_ADDR_LEN];
    std::uint16_t   ether_type;
};

struct ip_header {
    std::uint8_t    ip_vhl;
    std::uint8_t    ip_tos;
    std::uint16_t   ip_len;
    std::uint16_t   ip_id;
    std::uint16_t   ip_off;

    std::uint8_t    ip_ttl;
    std::uint8_t    ip_p;
    std::uint16_t   ip_sum;

    in_addr         ip_src;
    in_addr         ip_dst;
};

struct tcp_header {
    std::uint16_t   th_sport;
    std::uint16_t   th_dport;
    std::uint32_t   th_seq;
    std::uint32_t   th_ack;
    std::uint8_t    th_offx2;
    std::uint8_t    th_flags;
    std::uint16_t   th_win;
    std::uint16_t   th_sum;
    std::uint16_t   th_urp;
};

#pragma pack(pop)

constexpr std::uint16_t IP_RF       = 0x8000;
constexpr std::uint16_t IP_DF       = 0x4000;
constexpr std::uint16_t IP_MF       = 0x2000;
constexpr std::uint16_t IP_OFFMASK  = 0x1FFF;

inline std::uint8_t IP_HL(const ip_header* ip) {
    return ip->ip_vhl & 0x0F;
}

inline std::uint8_t IP_V(const ip_header* ip) {
    return ip->ip_vhl >> 4;
}

constexpr std::uint8_t TH_FIN  = 0x01;
constexpr std::uint8_t TH_SYN  = 0x02;
constexpr std::uint8_t TH_RST  = 0x04;
constexpr std::uint8_t TH_PUSH = 0x08;
constexpr std::uint8_t TH_ACK  = 0x10;
constexpr std::uint8_t TH_URG  = 0x20;
constexpr std::uint8_t TH_ECE  = 0x40;
constexpr std::uint8_t TH_CWR  = 0x80;
constexpr std::uint8_t TH_FLAGS = TH_FIN | TH_SYN | TH_RST | TH_ACK | TH_URG | TH_ECE | TH_CWR;

inline std::uint8_t TH_OFF(const tcp_header* tcp) {
    return (tcp->th_offx2 & 0xF0) >> 4;
}
