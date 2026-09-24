# PacketReplayer-UDP-TCP-
A multi-threaded C++/Qt6 desktop application using PcapPlusPlus and CMake to parse, filter, and replay PCAP/PCAPNG network packet captures over TCP/UDP sockets. Features asynchronous background parsing via QThread architectures and dynamic BPF packet streaming rules without blocking main UI thread performance.

# Multi-Threaded Network Packet Analyzer & Replay Engine

A high-performance C++/Qt6 desktop application leveraging the **PcapPlusPlus API** to extract, filter, and stream deep network metadata from packet capture files (`.pcap`/`.pcapng`) asynchronously over raw network sockets.

## 🚀 Key Features

* **Asynchronous Multi-Threaded Parsing:** Offloads intensive file operations and network streaming onto isolated background tasks using `QThread` architectures, ensuring zero main-thread blockage and absolute UI responsiveness.
* **Deep Metadata Indexing:** Implements structural data routing via composite `QMap` and `QSet` hierarchies to map unique multi-variable network pathways, facilitating instant, multi-level traffic filtering.
* **Granular Network Replay Engine:** Assembles programmatic **BPF (Berkeley Packet Filter)** configurations to extract payloads and pipe them out via native `QTcpSocket` and `QUdpSocket` mechanisms.
* **Precision Pacing Controls:** Utilizes microsecond-accurate event loop mechanics and `QTimer` integrations allowing adjustable packet transmission speeds (Packets/Second).
* **Modern Cross-Platform Build System:** Fully configured using target-based **Modern CMake** to automate dependency management, asset loading, and Qt Meta-Object creation.

---

## 🛠️ Tech Stack & Dependencies

* **Language:** Modern C++ (C++17 Compliance)
* **Framework:** Qt Framework 6.x (Widgets, Network, Core Architecture, Threads)
* **Libraries:** PcapPlusPlus API (Core capture-parsing utilities)
* **Build System:** Modern CMake (3.16+)

