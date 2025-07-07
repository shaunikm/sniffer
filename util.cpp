//
// Created by Shaunik Musukula on 7/7/25.
//

#include "util.h"

#include <iomanip>

using namespace std::chrono;

[[nodiscard]] std::string now_string() {
    const auto tp = system_clock::now();
    const auto t  = system_clock::to_time_t(tp);
    const auto ms = duration_cast<milliseconds>(tp.time_since_epoch()) % 1000;

    std::ostringstream os;
    os << std::put_time(std::localtime(&t), "%H:%M:%S")
       << '.' << std::setw(3) << std::setfill('0') << ms.count();
    return os.str();
}

[[nodiscard]] std::string human_bytes(std::size_t b) {
    constexpr const char* units[]{"B","KB","MB","GB","TB"};
    auto val = static_cast<double>(b);
    std::size_t idx = 0;
    while (val >= 1024.0 && idx < std::size(units) - 1) {
        val /= 1024.0;
        ++idx;
    }
    std::ostringstream os;
    os << std::fixed << std::setprecision(1) << val << ' ' << units[idx]
       << " (" << b << ')';
    return os.str();
}

void hex_line(WINDOW* w, const int y, const std::uint8_t* d, const std::size_t len, const std::size_t off) {
    mvwprintw(w, y, 1, "%04zx  ", off);
    attr_t save; short pair; wattr_get(w, &save, &pair, nullptr);

    for (int i = 0; i < 16; ++i) {
        wprintw(w, i < static_cast<int>(len) ? "%02x " : "   ", i < static_cast<int>(len) ? d[i] : 0);
    }
    wprintw(w, " ");
    for (int i = 0; i < 16; ++i) {
        wprintw(w,
                i < static_cast<int>(len) ? (std::isprint(d[i]) ? "%c" : ".") : " ",
                d[i]);
    }
}
