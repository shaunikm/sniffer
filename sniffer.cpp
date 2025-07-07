#include "net_types.h"
#include "netdev_lookup.h"

#include <pcap/pcap.h>
#include <ncurses.h>

#include <arpa/inet.h>
#include <atomic>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <string>
#include <vector>
#include <cmath>
#include <algorithm>

struct Row {
    std::string               ts, src, dst, proto;
    std::size_t               len{};
    std::vector<std::uint8_t> payload;
};

struct Counters {
    std::atomic<std::size_t> all{0}, tcp{0}, udp{0}, icmp{0}, other{0}, bytes{0};
    void clear() { all = tcp = udp = icmp = other = bytes = 0; }
};

constexpr int MAX_ROWS = 1000;

static std::vector<Row> rows;
static Counters cnt;
static std::vector<DeviceMapping> devices;

static bool paused   = false;
static bool showHex  = false;
static std::size_t curDev = 0;

static pcap_t* handle = nullptr;
static char err[PCAP_ERRBUF_SIZE]{};

static std::size_t selected = 0;
static std::size_t firstVis = 0;

static WINDOW *wStats = nullptr, *wTable = nullptr, *wHex = nullptr;

std::string now_string() {
    using namespace std::chrono;
    const auto tp = system_clock::now();
    const auto t  = system_clock::to_time_t(tp);
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;
    std::ostringstream o;
    o << std::put_time(std::localtime(&t), "%H:%M:%S")
      << '.' << std::setw(3) << std::setfill('0') << ms.count();
    return o.str();
}

std::string human_bytes(std::size_t b) {
    static const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    double val = b;
    int i = 0;
    while (val >= 1024 && i < 4) {
        val /= 1024;
        ++i;
    }
    std::ostringstream o;
    o << std::fixed << std::setprecision(1) << val << ' ' << units[i] << " (" << b << ')';
    return o.str();
}

void hex_line(WINDOW* win, int y, const std::uint8_t* data, std::size_t len, std::size_t off) {
    mvwprintw(win, y, 1, "%04zx  ", off);
    for (int i = 0; i < 16; ++i)
        wprintw(win, i < len ? "%02x " : "   ", i < len ? data[i] : 0);
    wprintw(win, " ");
    for (int i = 0; i < 16; ++i)
        if (i < len)
            wprintw(win, "%c", std::isprint(data[i]) ? data[i] : '.');
}

void draw_stats() {
    werase(wStats); box(wStats, 0, 0); wattron(wStats, A_BOLD);
    mvwprintw(wStats, 0, 2, "Dev: %s (%s)", devices[curDev].iface->name, devices[curDev].description.c_str());
    mvwprintw(wStats, 1, 1, "Pk: %zu TCP: %zu UDP: %zu ICMP: %zu Oth: %zu  Bytes: %s",
        cnt.all.load(), cnt.tcp.load(), cnt.udp.load(), cnt.icmp.load(), cnt.other.load(),
        human_bytes(cnt.bytes.load()).c_str());
    wattroff(wStats, A_BOLD); wnoutrefresh(wStats);
}

void draw_table() {
    werase(wTable); box(wTable, 0, 0);
    int maxy, maxx; getmaxyx(wTable, maxy, maxx);
    int innerH = maxy - 3;
    wattron(wTable, A_UNDERLINE);
    mvwprintw(wTable, 1, 1, "Time        Source             → Destination        Pr  Len");
    wattroff(wTable, A_UNDERLINE);
    for (int line = 0; line < innerH; ++line) {
        std::size_t off = firstVis + line;
        if (off >= rows.size()) break;
        const Row& r = rows[rows.size() - 1 - off];
        bool sel = (off == selected);
        if (sel) wattron(wTable, A_REVERSE);
        mvwprintw(wTable, 2 + line, 1, "%s  %-15s → %-15s  %-3s %5zu",
                  r.ts.c_str(), r.src.c_str(), r.dst.c_str(), r.proto.c_str(), r.len);
        if (sel) wattroff(wTable, A_REVERSE);
    }
    wnoutrefresh(wTable);
}

void draw_hex() {
    werase(wHex); box(wHex, 0, 0);
    if (!showHex || rows.empty()) { wnoutrefresh(wHex); return; }
    if (selected >= rows.size()) selected = rows.size() - 1;
    const Row& r = rows[rows.size() - 1 - selected];
    mvwprintw(wHex, 1, 1, "Hex dump (%zu bytes)", r.payload.size());
    int maxy, maxx; getmaxyx(wHex, maxy, maxx);
    for (std::size_t off = 0, line = 2; off < r.payload.size() && line < maxy - 1; off += 16, ++line)
        hex_line(wHex, line, r.payload.data() + off, std::min<std::size_t>(16, r.payload.size() - off), off);
    wnoutrefresh(wHex);
}

void refresh_ui() {
    draw_stats();
    draw_table();
    draw_hex();
    doupdate();
}

void open_device(std::size_t idx) {
    if (handle) pcap_close(handle);
    handle = pcap_open_live(devices[idx].iface->name, BUFSIZ, PROMISCUOUS_MODE, 1000, err);
    if (!handle) { endwin(); fprintf(stderr, "%s\n", err); exit(1); }
    pcap_setnonblock(handle, 1, err);
    rows.clear(); cnt.clear();
    selected = firstVis = 0;
}

void maintain_selection() {
    if (selected > 0) {
        ++selected;
        if (selected >= rows.size()) selected = rows.size() - 1;
    }
}

void pkt_cb(u_char*, const pcap_pkthdr* h, const u_char* pkt) {
    if (paused) return;
    const auto ip = reinterpret_cast<const ip_header*>(pkt + SIZE_ETHERNET);

    Row r {
        .ts      = now_string(),
        .src     = inet_ntoa(ip->ip_src),
        .dst     = inet_ntoa(ip->ip_dst),
        .proto   = "",
        .len     = h->len
    };

    switch (ip->ip_p) {
        case IPPROTO_TCP: ++cnt.tcp; r.proto = "TCP"; break;
        case IPPROTO_UDP: ++cnt.udp; r.proto = "UDP"; break;
        case IPPROTO_ICMP: ++cnt.icmp; r.proto = "ICMP"; break;
        default: ++cnt.other; r.proto = "OTH"; break;
    }

    ++cnt.all;
    cnt.bytes += h->len;

    if (showHex) {
        std::size_t ipLen = IP_HL(ip) * 4;
        const auto* pl = pkt + SIZE_ETHERNET + ipLen;
        std::size_t plLen = h->caplen - (pl - pkt);
        r.payload.assign(pl, pl + plLen);
    }

    if (rows.size() == MAX_ROWS) rows.erase(rows.begin());
    rows.emplace_back(std::move(r));
    maintain_selection();
}

void enumerate_devices() {
    pcap_if_t* list = nullptr;
    if (pcap_findalldevs(&list, err) == PCAP_ERROR) {
        fprintf(stderr, "%s\n", err);
        exit(1);
    }

    for (auto* d = list; d; d = d->next)
        devices.push_back(match_iface_pcap(d));

    if (devices.empty()) {
        fprintf(stderr, "No devices\n");
        exit(1);
    }
}

void device_popup() {
    int H, W;
    getmaxyx(stdscr, H, W);
    const int boxH = std::min<int>(static_cast<int>(devices.size()) + 2, H - 4);
    const int boxW = W / 2;
    const int startY = (H - boxH) / 2;
    const int startX = (W - boxW) / 2;

    WINDOW* pop = newwin(boxH, boxW, startY, startX);
    box(pop, 0, 0); keypad(pop, TRUE);

    int sel = 0;
    while (true) {
        for (int i = 0; i < boxH - 2; ++i) {
            const int idx = i;
            if (idx >= devices.size()) break;
            if (idx == sel) wattron(pop, A_REVERSE);
            mvwprintw(pop, 1 + i, 1, "%s (%s)", devices[idx].iface->name, devices[idx].description.c_str());
            if (idx == sel) wattroff(pop, A_REVERSE);
        }
        wrefresh(pop);
        if (const int ch = wgetch(pop); ch == KEY_UP && sel > 0) --sel;
        else if (ch == KEY_DOWN && sel < static_cast<int>(devices.size()) - 1) ++sel;
        else if (ch == '\n') { curDev = sel; delwin(pop); open_device(curDev); return; }
        else if (ch == 27)    { delwin(pop); return; }
    }
}

int main() {
    enumerate_devices();
    initscr(); cbreak(); noecho(); curs_set(0);
    keypad(stdscr, TRUE); nodelay(stdscr, TRUE);

    int H, W;
    getmaxyx(stdscr, H, W);
    const int statsH = 3, hexH = H / 3, tableH = H - statsH - hexH;

    wStats = newwin(statsH, W, 0, 0);
    wTable = newwin(tableH, W, statsH, 0);
    wHex   = newwin(hexH, W, statsH + tableH, 0);
    keypad(wTable, TRUE);

    open_device(curDev);

    bool run = true;
    while (run) {
        pcap_dispatch(handle, 64, pkt_cb, nullptr);

        int maxy, maxx;
        getmaxyx(wTable, maxy, maxx);
        const int visH = maxy - 3;

        if (selected == 0)
            firstVis = 0;
        else if (selected - firstVis >= visH)
            firstVis = selected - visH + 1;
        else if (selected < firstVis)
            firstVis = selected;

        refresh_ui();

        switch (getch()) {
            case 'q': run = false; break;
            case 'p': paused = !paused; break;
            case 'h': showHex = !showHex; break;
            case 'd': device_popup(); break;
            case KEY_UP:   if (selected < rows.size() - 1) ++selected; break;
            case KEY_DOWN: if (selected > 0) --selected; break;
            default: break;
        }

        napms(35);
    }

    endwin();
    if (handle) pcap_close(handle);
    printf("\nCapture finished.\n");
    return 0;
}
