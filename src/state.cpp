//
// Created by Shaunik Musukula on 7/6/25.
//

#include "state.h"

std::vector<Row>           gRows;
Counters                   gCnt;
bool                       gPaused   = false;
bool                       gShowHex  = false;
std::vector<DeviceMapping> gDevices;
std::size_t                gCurDev   = 0;
pcap_t*                    gHandle   = nullptr;
pcap_dumper_t*             gDumper   = nullptr;
char                       gErr[PCAP_ERRBUF_SIZE]{};
std::size_t                gSelected = 0;
std::size_t                gFirstVis = 0;
CaptureLimit               gCapLim;
std::size_t                gBps = 0;