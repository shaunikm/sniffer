//
// Created by Shaunik Musukula on 7/7/25.
//

#include "pcap_helpers.h"
#include "state.h"
#include "util.h"
#include "rendering.h"
#include "net_types.h"

void open_device(const std::size_t idx) {
    if (gHandle) {
        pcap_close(gHandle);
        gHandle = nullptr;
    }

    gHandle = pcap_open_live(gDevices[idx].iface->name,
                             BUFSIZ,
                             PROMISCUOUS_MODE,
                             1'000,
                             gErr);
    if (!gHandle) {
        endwin();
        std::fprintf(stderr, "%s\n", gErr);
        std::exit(EXIT_FAILURE);
    }

    gDumper = pcap_dump_open(gHandle, "capture.pcap");
    if (!gDumper) {
        std::fprintf(stderr, "Couldn't open dump file: %s\n", pcap_geterr(gHandle));
    }

    pcap_setnonblock(gHandle, 1, gErr);

    gRows.clear();
    gCnt.clear();
    gSelected = gFirstVis = 0;
    gCapLim.reset();
}

void maintain_selection() {
    if (gSelected > 0) {
        ++gSelected;
        if (gSelected >= gRows.size()) gSelected = gRows.size() - 1;
    }
}

void packet_cb([[maybe_unused]] std::uint8_t* user,
               const pcap_pkthdr* h,
               const std::uint8_t*      pkt) {
    if (gPaused || gCapLim.hit(gCnt)) return;
    if (gDumper) pcap_dump(reinterpret_cast<std::uint8_t* >(gDumper), h, pkt);

    const auto* ip = reinterpret_cast<const ip_header* >(pkt + SIZE_ETHERNET);
    Row          r{now_string(), inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), "", h->len};

    switch (ip->ip_p) {
        case IPPROTO_TCP: ++gCnt.tcp;   r.proto = "TCP";   break;
        case IPPROTO_UDP: ++gCnt.udp;   r.proto = "UDP";   break;
        case IPPROTO_ICMP:++gCnt.icmp;  r.proto = "ICMP";  break;
        default:          ++gCnt.other; r.proto = "OTH";   break;
    }

    ++gCnt.all;
    gCnt.bytes += h->len;

    if (gShowHex) {
        const std::size_t ip_len = IP_HL(ip)*  4;
        const auto*       pl     = pkt + SIZE_ETHERNET + ip_len;
        const std::size_t pl_len = h->caplen - static_cast<std::size_t>(pl - pkt);
        r.payload.assign(pl, pl + pl_len);
    }

    if (gRows.size() == MAX_ROWS) gRows.erase(gRows.begin());
    gRows.emplace_back(std::move(r));
    maintain_selection();
}