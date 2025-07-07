cmake_minimum_required(VERSION 3.10)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)

find_library(PCAP_LIBRARY pcap REQUIRED)
find_library(NCURSES_LIBRARY ncurses REQUIRED)

add_executable(sniffer sniffer.cpp
        netdev_lookup.cpp
        netdev_lookup.h
        net_types.cpp
        net_types.h)

target_link_libraries(sniffer ${PCAP_LIBRARY} ${NCURSES_LIBRARY})
