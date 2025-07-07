# packet sniffer

## prereqs

- make
- cmake
- libpcap/pcap
- a c++ compiler (like clang or g++)

## running the program

run the following commands in the root directory

```bash
mkdir -p build
cd build
cmake ..
make
```

the `pcap` library requires elevated privileges to jack packets, so use this to run the packet sniffer

```bash
sudo ./sniffer
```

## controls

```
'up/down key' - selec packet
'c' - set a specific capture window (by packets, bytes, or a time interval). this will save captures packets to a .pcap file in the directory the executable is ran.
'h' - dump hex data of selected packet
'd' - select network interface to monitor
```

## implemenetation notes

- the interface descriptions were created for standard macOS network interfaces. descriptions are specificed in `src/netdev_lookup.cpp`
- at the top, you will see a measure of the throughput and total size of packets sent/recieved since the start of the capture. the exact number of bytes for each of these measurements is in the parentheses.
