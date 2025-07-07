//
// Created by Shaunik Musukula on 7/6/25.
//

#include "rendering.h"
#include "state.h"
#include "util.h"

void draw_stats() {
    werase(wStats);
    box(wStats, 0, 0);
    wattron(wStats, A_BOLD);
    mvwprintw(wStats, 0, 2, "Dev:%s (%s)",
               gDevices[gCurDev].iface->name,
               gDevices[gCurDev].description.c_str());
    mvwprintw(wStats, 1, 1,
              "Pk: %zu  TCP: %zu UDP: %zu ICMP: %zu Oth: %zu  Bytes: %s Bytes/second: %s/s",
              gCnt.all.load(), gCnt.tcp.load(), gCnt.udp.load(), gCnt.icmp.load(),
              gCnt.other.load(), human_bytes(gCnt.bytes.load()).c_str(),
              human_bytes(gBps).c_str());
    wattroff(wStats, A_BOLD);
    wnoutrefresh(wStats);
}

void draw_table() {
    werase(wTable);
    box(wTable, 0, 0);

    int h, w; getmaxyx(wTable, h, w);
    const int inner = h - 3;

    wattron(wTable, A_UNDERLINE);
    mvwprintw(wTable, 1, 1, "Time        Source\t\tDestination        Pr  Len");
    wattroff(wTable, A_UNDERLINE);

    for (int i = 0; i < inner; ++i) {
        const std::size_t off = gFirstVis + i;
        if (off >= gRows.size()) break;

        const Row &r = gRows[gRows.size() - 1 - off];
        const bool sel = (off == gSelected);
        if (sel) wattron(wTable, A_REVERSE);

        mvwprintw(wTable, 2 + i, 1,
                  "%s  %-15s\t%-15s  %-3s %5zu",
                  r.ts.c_str(), r.src.c_str(), r.dst.c_str(),
                  r.proto.c_str(), r.len);

        if (sel) wattroff(wTable, A_REVERSE);
    }
    wnoutrefresh(wTable);
}

void draw_hex() {
    werase(wHex);
    box(wHex, 0, 0);
    if (!gShowHex || gRows.empty()) { wnoutrefresh(wHex); return; }

    if (gSelected >= gRows.size()) gSelected = gRows.size() - 1;
    const Row &r = gRows[gRows.size() - 1 - gSelected];
    mvwprintw(wHex, 1, 1, "Hex dump (%zu bytes)", r.payload.size());

    int h, w; getmaxyx(wHex, h, w);
    std::size_t off = 0; int line = 2;
    while (off < r.payload.size() && line < h - 1) {
        const std::size_t chunk = std::min<std::size_t>(16, r.payload.size() - off);
        hex_line(wHex, line++, r.payload.data() + off, chunk, off);
        off += chunk;
    }
    wnoutrefresh(wHex);
}

void refresh_render() {
    draw_stats();
    draw_table();
    draw_hex();
    doupdate();
}