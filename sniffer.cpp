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

static constexpr int MAX_ROWS = 400;
static std::vector<Row> rows;
static Counters         cnt;
static bool             paused  = false;
static bool             showHex = false;

static std::vector<DeviceMapping> devices;
static std::size_t                curDev = 0;
static pcap_t*                    handle = nullptr;
static char                       err[PCAP_ERRBUF_SIZE]{};

static WINDOW *wStats = nullptr, *wTable = nullptr, *wHex = nullptr;

std::string now_string() {
    using namespace std::chrono;
    const auto tp = system_clock::now();
    const auto t  = system_clock::to_time_t(tp);
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;

    std::ostringstream oss;
    oss << std::put_time(std::localtime(&t), "%H:%M:%S") << '.'
        << std::setw(3) << std::setfill('0') << ms.count();
    return oss.str();
}

void hex_line(WINDOW* win, int y, const std::uint8_t* data, const std::size_t len, const std::size_t off) {
    mvwprintw(win, y, 0, "%04zx  ", off);
    for (int i = 0; i < 16; ++i)
        wprintw(win, i < len ? "%02x " : "   ", i < len ? data[i] : 0);
    wprintw(win, " ");
    for (int i = 0; i < 16; ++i)
        if (i < len) wprintw(win, "%c", std::isprint(data[i]) ? data[i] : '.');
}

void draw_stats() {
    werase(wStats);
    wattron(wStats, A_BOLD);
    mvwprintw(wStats, 0, 0,
        "Dev:%s (%s)  Pk:%zu TCP:%zu UDP:%zu ICMP:%zu Oth:%zu  Bytes:%zu  (p pause | h hex | d dev | q quit)",
        devices[curDev].iface->name, devices[curDev].description.c_str(),
        cnt.all.load(), cnt.tcp.load(), cnt.udp.load(), cnt.icmp.load(),
        cnt.other.load(), cnt.bytes.load());
    wattroff(wStats, A_BOLD);
    wnoutrefresh(wStats);
}

void draw_table() {
    werase(wTable);
    wattron(wTable, A_UNDERLINE);
    mvwprintw(wTable, 0, 0, "Time          Source\t\tDestination       Pr  Len");
    wattroff(wTable, A_UNDERLINE);

    int maxy, maxx;
    getmaxyx(wTable, maxy, maxx);

    int y = 1;
    for (int i = static_cast<int>(rows.size()) - 1; i >= 0 && y < maxy; --i, ++y) {
        const Row& r = rows[i];
        mvwprintw(wTable, y, 0, "%s  %-15s\t%-15s  %-3s %5zu",
                  r.ts.c_str(), r.src.c_str(), r.dst.c_str(), r.proto.c_str(), r.len);
    }

    wnoutrefresh(wTable);
}

void draw_hex() {
    werase(wHex);
    if (!showHex || rows.empty()) {
        wnoutrefresh(wHex);
        return;
    }

    const Row& r = rows.back();
    mvwprintw(wHex, 0, 0, "Hex (%zu bytes)", r.payload.size());

    int maxy, maxx;
    getmaxyx(wHex, maxy, maxx);

    for (std::size_t off = 0, line = 1; off < r.payload.size() && line < maxy; off += 16, ++line)
        hex_line(wHex, line, r.payload.data() + off, std::min<std::size_t>(16, r.payload.size() - off), off);

    wnoutrefresh(wHex);
}

void refresh_ui() {
    draw_stats();
    draw_table();
    draw_hex();
    doupdate();
}

void open_device(const std::size_t idx) {
    if (handle)
        pcap_close(handle);

    handle = pcap_open_live(devices[idx].iface->name, BUFSIZ, PROMISCUOUS_MODE, 1000, err);
    if (!handle) {
        snprintf(err, sizeof(err), "Couldn't open %s", devices[idx].iface->name);
        endwin();
        fprintf(stderr, "%s\n", err);
        exit(1);
    }

    pcap_setnonblock(handle, 1, err);
    rows.clear();
    cnt.clear();
}

void pkt_cb(u_char*, const pcap_pkthdr* h, const u_char* pkt) {
    if (paused) return;

    const auto ip = reinterpret_cast<const ip_header*>(pkt + SIZE_ETHERNET);
    Row r{now_string(), inet_ntoa(ip->ip_src), inet_ntoa(ip->ip_dst), "", h->len};

    switch (ip->ip_p) {
        case IPPROTO_TCP: ++cnt.tcp; r.proto = "TCP"; break;
        case IPPROTO_UDP: ++cnt.udp; r.proto = "UDP"; break;
        case IPPROTO_ICMP: ++cnt.icmp; r.proto = "ICMP"; break;
        default: ++cnt.other; r.proto = "OTH";
    }

    ++cnt.all;
    cnt.bytes += h->len;

    if (showHex) {
        const std::size_t ipLen = IP_HL(ip) * 4;
        const auto* pl = pkt + SIZE_ETHERNET + ipLen;
        const std::size_t plLen = h->caplen - (pl - pkt);
        r.payload.assign(pl, pl + plLen);
    }

    if (rows.size() == MAX_ROWS)
        rows.erase(rows.begin());

    rows.emplace_back(std::move(r));
}

void enumerate_devices() {
    char errbuf[PCAP_ERRBUF_SIZE]{};
    pcap_if_t* list = nullptr;

    if (pcap_findalldevs(&list, errbuf) == PCAP_ERROR) {
        fprintf(stderr, "%s\n", errbuf);
        exit(1);
    }

    for (auto* d = list; d; d = d->next)
        devices.push_back(match_iface_pcap(d));

    if (devices.empty()) {
        fprintf(stderr, "No capture devices found\n");
        exit(1);
    }
}

int main() {
    enumerate_devices();

    initscr(); cbreak(); noecho(); curs_set(0); nodelay(stdscr, TRUE);

    int H, W;
    getmaxyx(stdscr, H, W);

    const int statsH = 1, hexH = H / 3, tableH = H - statsH - hexH;
    wStats = newwin(statsH, W, 0, 0);
    wTable = newwin(tableH, W, statsH, 0);
    wHex   = newwin(hexH, W, statsH + tableH, 0);

    open_device(curDev);

    bool run = true;
    while (run) {
        pcap_dispatch(handle, 64, pkt_cb, nullptr);
        refresh_ui();

        switch (getch()) {
            case 'q': run = false; break;
            case 'p': paused = !paused; break;
            case 'h': showHex = !showHex; break;
            case 'd': curDev = (curDev + 1) % devices.size(); open_device(curDev); break;
            default: break;
        }

        napms(40); // 25 fps
    }

    endwin();
    pcap_close(handle);
    printf("\nCapture finished.\n");
}
