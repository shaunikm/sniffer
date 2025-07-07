cmake_minimum_required(VERSION 3.10)
project(sniffer)

set(CMAKE_CXX_STANDARD 17)

include_directories(${PROJECT_SOURCE_DIR}/include /opt/homebrew/include)
link_directories(/opt/homebrew/lib)

find_library(PCAP_LIBRARY pcap REQUIRED)
find_library(NCURSES_LIBRARY ncurses REQUIRED)

set(SRC_FILES
        src/sniffer.cpp
        src/netdev_lookup.cpp
        src/net_types.cpp
        src/state.cpp
        src/rendering.cpp
        src/util.cpp
        src/pcap_helpers.cpp
)

add_executable(sniffer ${SRC_FILES})

target_link_libraries(sniffer ${PCAP_LIBRARY} ${NCURSES_LIBRARY})
