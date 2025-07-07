#include "net_types.h"
#include "netdev_lookup.h"
#include "state.h"
#include "rendering.h"
#include "pcap_helpers.h"

#include <pcap/pcap.h>
#include <ncurses.h>
#include <arpa/inet.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>
#include <sstream>
#include <string>
#include <vector>

namespace dev {
    void enumerate() {
        pcap_if_t* list = nullptr;
        if (pcap_findalldevs(&list, gErr) == PCAP_ERROR) {
            std::fprintf(stderr, "%s\n", gErr);
            std::exit(EXIT_FAILURE);
        }
        for (auto* d = list; d; d = d->next) gDevices.emplace_back(match_iface_pcap(d));
        if (gDevices.empty()) {
            std::fprintf(stderr, "No devices found\n");
            std::exit(EXIT_FAILURE);
        }
    }

    void popup() {
        int H, W; getmaxyx(stdscr, H, W);
        const int box_h = std::min<int>(static_cast<int>(gDevices.size()) + 2, H - 4);
        const int box_w = W / 2;
        const int y0    = (H - box_h) / 2;
        const int x0    = (W - box_w) / 2;

        WINDOW* pop = newwin(box_h, box_w, y0, x0);
        box(pop, 0, 0);
        keypad(pop, TRUE);

        int sel = 0;
        while (true) {
            werase(pop);
            box(pop, 0, 0);
            for (int i = 0; i < box_h - 2; ++i) {
                const int idx = i;
                if (idx >= static_cast<int>(gDevices.size())) break;
                if (idx == sel) wattron(pop, A_REVERSE);
                mvwprintw(pop, 1 + i, 1, "%-10s  %s",
                           gDevices[idx].iface->name,
                           gDevices[idx].description.c_str());
                if (idx == sel) wattroff(pop, A_REVERSE);
            }
            wrefresh(pop);
            if (const int ch = wgetch(pop); ch == KEY_UP && sel > 0)              --sel;
            else if (ch == KEY_DOWN && sel < static_cast<int>(gDevices.size()) - 1) ++sel;
            else if (ch == '\n') { gCurDev = sel; delwin(pop); open_device(gCurDev); return; }
            else if (ch == 27)   { delwin(pop); return; }
        }
    }
}

namespace limit {
    void popup() {
        static constexpr const char* kinds[]{"Packets","Bytes","Seconds"};

        int H, W; getmaxyx(stdscr, H, W);
        constexpr int box_h = 8, box_w = 32;
        const int y0 = (H - box_h) / 2, x0 = (W - box_w) / 2;

        WINDOW* pop = newwin(box_h, box_w, y0, x0);
        box(pop, 0, 0);
        keypad(pop, TRUE);
        echo();

        int         kind_sel = 0;
        std::string num;

        while (true) {
            werase(pop);
            box(pop, 0, 0);
            mvwprintw(pop, 1, 2, "Stop after:");
            for (int i = 0; i < 3; ++i) {
                if (i == kind_sel) wattron(pop, A_REVERSE);
                mvwprintw(pop, 2 + i, 4, "%s", kinds[i]);
                if (i == kind_sel) wattroff(pop, A_REVERSE);
            }
            mvwprintw(pop, 6, 2, "Value: %s", num.c_str());
            wrefresh(pop);

            if (const int ch = wgetch(pop); ch == KEY_UP && kind_sel > 0)               --kind_sel;
            else if (ch == KEY_DOWN && kind_sel < 2)        ++kind_sel;
            else if (std::isdigit(ch))                      num.push_back(static_cast<char>(ch));
            else if (ch == KEY_BACKSPACE || ch == 127) {
                if (!num.empty()) num.pop_back();
            } else if (ch == '\n' && !num.empty()) {
                gCapLim.kind   = kind_sel == 0 ? LimitKind::kPackets
                                   : kind_sel == 1 ? LimitKind::kBytes
                                                   : LimitKind::kSeconds;
                gCapLim.target = std::stoull(num);
                gCapLim.start  = std::chrono::steady_clock::now();
                delwin(pop);
                noecho();
                return;
            } else if (ch == 27) {
                delwin(pop);
                noecho();
                return;
            }
        }
    }
}

int main() {
    dev::enumerate();

    initscr();
    cbreak();
    noecho();
    curs_set(0);
    keypad(stdscr, TRUE);
    nodelay(stdscr, TRUE);

    int H, W; getmaxyx(stdscr, H, W);
    init_windows(H, W);

    open_device(gCurDev);

    std::size_t                last_bytes = 0;
    auto                       last_tick  = std::chrono::steady_clock::now();
    bool                       running    = true;

    while (running) {
        pcap_dispatch(gHandle, DISPATCH_BULK, packet_cb, nullptr);

        if (auto now = std::chrono::steady_clock::now(); now - last_tick >= std::chrono::seconds{1}) {
            const std::size_t cur = gCnt.bytes.load();
            gBps       = cur - last_bytes;
            last_bytes = cur;
            last_tick  = now;
        }

        int h_tbl, _;
        getmaxyx(wTable, h_tbl, _);
        const int visible = h_tbl - 3;
        if (gSelected == 0) gFirstVis = 0;
        else if (static_cast<int>(gSelected - gFirstVis) >= visible) gFirstVis = gSelected - visible + 1;
        else if (gSelected < gFirstVis) gFirstVis = gSelected;

        refresh_render();

        if (gCapLim.hit(gCnt)) { running = false; continue; }

        switch (getch()) {
            case 'q': running = false; break;
            case 'p': gPaused = !gPaused; break;
            case 'h': gShowHex = !gShowHex; break;
            case 'd': dev::popup(); break;
            case 'c': limit::popup(); break;
            case KEY_UP:   if (gSelected < gRows.size() - 1) ++gSelected; break;
            case KEY_DOWN: if (gSelected > 0)               --gSelected; break;
            default: break;
        }
        napms(UI_NAP_MS);
    }

    endwin();
    if (gDumper) { pcap_dump_close(gDumper); gDumper = nullptr; }
    pcap_close(gHandle);

    std::puts("\nCapture finished.");
    return 0;
}
