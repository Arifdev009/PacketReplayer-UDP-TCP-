cmake_minimum_required(VERSION 3.19)
project(PacketReplayer LANGUAGES CXX)

find_package(Qt6 6.5 REQUIRED COMPONENTS Core Widgets Network)
find_package(Qt6 REQUIRED COMPONENTS Core)
find_package(Qt6 REQUIRED COMPONENTS Core)

qt_standard_project_setup()

qt_add_executable(PacketReplayer
    WIN32 MACOSX_BUNDLE
    main.cpp
    mainwindow.cpp
    mainwindow.h
    mainwindow.ui
    pcapfileparser.h pcapfileparser.cpp
    tcpclient.h tcpclient.cpp
    pcapfileFilter.h pcapfileFilter.cpp
    packetplayer.h packetplayer.cpp
    udpsender.h udpsender.cpp
)

# 1. Update the header inclusion paths
target_include_directories(PacketReplayer PRIVATE
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/PcapPlusPlus-26.07/Pcap++/header"
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/PcapPlusPlus-26.07/Packet++/header"
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/PcapPlusPlus-26.07/Common++/header"
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/npcap/Include"
)

# 2. Link directly to your natively compiled machine static binaries
target_link_libraries(PacketReplayer PRIVATE
    Qt::Core
    Qt::Widgets
    Qt::Network

    # Natively compiled static libraries
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/PcapPlusPlus-26.07/build/Pcap++/libPcap++.a"
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/PcapPlusPlus-26.07/build/Packet++/libPacket++.a"
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/PcapPlusPlus-26.07/build/Common++/libCommon++.a"

    # Hardware network driver interfaces
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/npcap/Lib/x64/wpcap.lib"
    "${CMAKE_CURRENT_SOURCE_DIR}/pcap/npcap/Lib/x64/Packet.lib"
    ws2_32
    iphlpapi
)
target_link_libraries(PacketReplayer PRIVATE Qt6::Core)
target_link_libraries(PacketReplayer PRIVATE Qt6::Core)



include(GNUInstallDirs)

install(TARGETS PacketReplayer
    BUNDLE  DESTINATION .
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

qt_generate_deploy_app_script(
    TARGET PacketReplayer
    OUTPUT_SCRIPT deploy_script
    NO_UNSUPPORTED_PLATFORM_ERROR
)
install(SCRIPT ${deploy_script})
