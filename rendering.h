//
// Created by Shaunik Musukula on 7/6/25.
//

#pragma once

#include <ncurses.h>

static WINDOW* wStats    = nullptr;
static WINDOW* wTable    = nullptr;
static WINDOW* wHex      = nullptr;

constexpr int  MAX_ROWS      = 1'000;
constexpr auto DISPATCH_BULK = 64;
constexpr auto UI_NAP_MS     = 35;

void init_windows(int H, int W);

void refresh_render();
