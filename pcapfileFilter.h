#ifndef PCAPFILEFILTER_H
#define PCAPFILEFILTER_H

#include <QObject>
#include <iostream>
#include "PcapFileDevice.h"
#include "PcapFilter.h"

#include "Packet.h"
#include "IPv4Layer.h"


#include <vector>
#include <cstdint>
#include "RawPacket.h"

// 1. Define the requested Enum
enum FragmentType {
    FIRST,
    MIDDLE,
    LAST,
    NOT_FRAGMENTED
};

// 2. Define the exact response structure
struct FragmentOutput {
    bool isFragmented = false;
    FragmentType type = NOT_FRAGMENTED;
    int fragmentNumber = 0;       // Sequence index (e.g. 1st fragment = 1, 2nd = 2)
    QByteArray payload; // The raw payload data slice
};

class pcapFileFilter : public QObject
{
    Q_OBJECT
public:
    pcapFileFilter(QObject *parent = nullptr);
    QVector<QByteArray> makeFilteredRawPackets(bool udportcp,QString filePath,QString srcIP,QString dstIP,QString srcPort,QString dstPort);

    FragmentOutput parseUdpRawPacketFragment(const pcpp::RawPacket &rawPacket);

    FragmentOutput parseTcpRawPacketFragment(const pcpp::RawPacket &rawPacket);
};

#endif // PCAPFILEFILTER_H
