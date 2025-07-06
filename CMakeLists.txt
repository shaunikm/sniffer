cmake_minimum_required(VERSION 3.10)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

include_directories(/opt/homebrew/include)
link_directories(/opt/homebrew/lib)

find_library(PCAP_LIBRARY pcap REQUIRED)

add_executable(sniffer main.cpp
        netdev_lookup.cpp
        netdev_lookup.h)

target_link_libraries(sniffer ${PCAP_LIBRARY})
