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


---

## ⚙️ Compilation & Environment Setup

This application requires the **Npcap Driver** to be installed on the host machine and depends on **PcapPlusPlus** compiled explicitly with the matching Qt MinGW compiler environment.

### 1. Prerequisites & Folder Structure
1. Download and install the [Npcap Driver](https://npcap.com).
2. Create a folder named `pcap` inside your main project root directory.
3. Download and extract the **Npcap SDK** and **PcapPlusPlus source files** into that directory matching this exact structure:
   ```text
   your-project/
   └── pcap/
       ├── npcap/              <-- Npcap SDK files
       └── PcapPlusPlus-26.07/ <-- Extracted PcapPlusPlus source framework
   ```

### 2. Building PcapPlusPlus with Qt's CMake & MinGW
Open your command prompt (`cmd`) and execute the following batch instructions sequentially to construct your dependency binaries:

```cmd
:: A. Bind Qt's CMake tool and MinGW 13.1.0 64-bit compiler to your terminal path environment
set PATH=C:\Qt\Tools\CMake_64\bin;%PATH%
set PATH=C:\Qt\Tools\mingw1310_64\bin;%PATH%

:: B. Verify binary visibility states match
cmake --version

:: C. Move directly into your extracted source framework folder and initialize a build target
cd C:\pcap\PcapPlusPlus-26.07
mkdir build
cd build

:: D. Generate the MinGW Makefiles pointing to the local Npcap installation paths
cmake -G "MinGW Makefiles" -DPCAPPLUSPLUS_BUILD_TESTS=OFF -DPCAP_ROOT="C:/pcap/npcap" -DCMAKE_CXX_FLAGS="-D_In_= -D_Post_invalid_=" ..

