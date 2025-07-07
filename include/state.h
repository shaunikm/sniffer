//
// Created by Shaunik Musukula on 7/6/25.
//

#pragma once

#include "netdev_lookup.h"
#include <vector>
#include <atomic>

#ifdef __cplusplus
extern "C" {
#endif

#include <pcap/pcap.h>

#ifdef __cplusplus
}
#endif

struct Row {
    std::string               ts;
    std::string               src;
    std::string               dst;
    std::string               proto;
    std::size_t               len{};
    std::vector<std::uint8_t> payload;
};

struct Counters {
    std::atomic<std::size_t> all{0}, tcp{0}, udp{0}, icmp{0}, other{0}, bytes{0};
    void clear() { all = tcp = udp = icmp = other = bytes = 0; }
};

enum class LimitKind { kNone, kPackets, kBytes, kSeconds };

struct CaptureLimit {
    LimitKind kind   = LimitKind::kNone;
    std::size_t                                    target = 0;
    std::chrono::steady_clock::time_point          start  = {};

    void reset() { kind = LimitKind::kNone; target = 0; }

    [[nodiscard]] bool hit(const Counters &c) const {
        using clock = std::chrono::steady_clock;
        switch (kind) {
            case LimitKind::kPackets: return c.all   >= target;
            case LimitKind::kBytes:   return c.bytes >= target;
            case LimitKind::kSeconds:
                return std::chrono::duration_cast<std::chrono::seconds>(clock::now() - start).count() >= target;
            default: return false;
        }
    }
};

extern std::vector<Row>             gRows;
extern Counters                     gCnt;
extern bool                         gPaused;
extern bool                         gShowHex;
extern std::vector<DeviceMapping>   gDevices;
extern std::size_t                  gCurDev;
extern pcap_t*                      gHandle;
extern pcap_dumper_t*               gDumper;
extern char                         gErr[PCAP_ERRBUF_SIZE];
extern std::size_t                  gSelected;
extern std::size_t                  gFirstVis;
extern CaptureLimit                 gCapLim;
extern std::size_t                  gBps;