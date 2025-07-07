//
// Created by Shaunik Musukula on 7/6/25.
//

#include "net_types.h"

#include <cctype>

void print_payload_hex(const std::uint8_t* payload, const std::size_t len) {
    constexpr int bytes_per_line = 16;

    for (std::size_t i = 0; i < len; i += bytes_per_line) {
        std::printf("%04zx  ", i);

        for (int j = 0; j < bytes_per_line; ++j) {
            if (i + j < len) {
                std::printf("%02x ", payload[i + j]);
            } else {
                std::printf("   ");
            }
        }

        std::printf(" ");

        for (int j = 0; j < bytes_per_line && i + j < len; ++j) {
            unsigned char c = payload[i + j];
            std::printf("%c", std::isprint(c) ? c : '.');
        }

        std::printf("\n");
    }
}