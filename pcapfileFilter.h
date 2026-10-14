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
// enum FragmentType {
//     FIRST,
//     MIDDLE,
//     LAST,
//     NOT_FRAGMENTED
// };
// struct FragmentOutput {
//     bool isFragmented = false;
//     FragmentType type = NOT_FRAGMENTED;
//     QByteArray payload;
//     uint32_t tcpSeqNum = 0;   // <--- Add this
//     int fragmentNumber = 0;   // Keep for IP logic compatibility
// };


// 1. Transaction block tracking structure
struct MessageBlock {
    QByteArray buffer;
    uint32_t expectedNextSeq = 0;
    bool hasHole = false;
    bool isFirstPacket = true;
};

// 2. Define the exact response structure
// struct FragmentOutput {
//     bool isFragmented = false;
//     FragmentType type = NOT_FRAGMENTED;
//     int fragmentNumber = 0;       // Sequence index (e.g. 1st fragment = 1, 2nd = 2)
//     QByteArray payload; // The raw payload data slice
// };

class pcapFileFilter : public QObject
{
    Q_OBJECT
public:
    pcapFileFilter(QObject *parent = nullptr);
    QVector<QByteArray> makeFilteredRawPackets(bool udportcp,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort);
    void parseUdpRawPackets(QVector<QByteArray>& payloadStorage,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort);
    void parseTcpRawPackets(QVector<QByteArray>& payloadStorage,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort);

    // FragmentOutput parseUdpRawPacketFragment(const pcpp::RawPacket &rawPacket);

    // FragmentOutput parseTcpRawPacketFragment(const pcpp::RawPacket &rawPacket);
};

#endif // PCAPFILEFILTER_H
