//
// Created by Shaunik Musukula on 7/7/25.
//

#pragma once

#include <ncurses.h>

#include <sstream>
#include <string>

std::string now_string();

std::string human_bytes(std::size_t b);

void hex_line(WINDOW* w, int y, const std::uint8_t* d, std::size_t len, std::size_t off);