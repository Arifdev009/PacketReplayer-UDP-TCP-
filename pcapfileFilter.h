#ifndef PCAPFILEFILTER_H
#define PCAPFILEFILTER_H

#include <QObject>
#include <QString>
#include <QSet>
#include <QVector>
#include <QByteArray>
#include <functional>

// Forward declare PcapPlusPlus structures to keep the header minimal
namespace pcpp {
class RawPacket;
}

enum FragmentType {
    FIRST,
    MIDDLE,
    LAST,
    NOT_FRAGMENTED
};

struct FragmentOutput {
    bool isFragmented = false;
    FragmentType type = NOT_FRAGMENTED;
    QByteArray payload;
    uint32_t tcpSeqNum = 0;
    int fragmentNumber = 0;
};

// Define functional callback type for slicing application layer byte streams
using MessageLengthDecoder = std::function<int(const QByteArray& buffer)>;

class pcapFileFilter : public QObject
{
    Q_OBJECT
public:
    explicit pcapFileFilter(QObject *parent = nullptr);

    // Primary Entry Point
    QVector<QByteArray> makeFilteredRawPackets(bool udportcp, QString filePath, QSet<QString> srcIP, QSet<QString> dstIP, QSet<QString> srcPort, QSet<QString> dstPort);

    // Processing Engines
    void parseUdpRawPackets(QVector<QByteArray>& payloadStorage, QString filePath, QSet<QString> srcIP, QSet<QString> dstIP, QSet<QString> srcPort, QSet<QString> dstPort);
    void parseTcpRawPackets(QVector<QByteArray>& payloadStorage, QString filePath, QSet<QString> srcIP, QSet<QString> dstIP, QSet<QString> srcPort, QSet<QString> dstPort, MessageLengthDecoder lengthDecoder);

    // Fragment Parsers
    // FragmentOutput parseUdpRawPacketFragment(const pcpp::RawPacket &rawPacket);
    // FragmentOutput parseTcpRawPacketFragment(const pcpp::RawPacket &rawPacket);
};

#endif // PCAPFILEFILTER_H

// 2. Define the exact response structure
// struct FragmentOutput {
//     bool isFragmented = false;
//     FragmentType type = NOT_FRAGMENTED;
//     int fragmentNumber = 0;       // Sequence index (e.g. 1st fragment = 1, 2nd = 2)
//     QByteArray payload; // The raw payload data slice
// };

// class pcapFileFilter : public QObject
// {
//     Q_OBJECT
// public:
//     pcapFileFilter(QObject *parent = nullptr);
//     QVector<QByteArray> makeFilteredRawPackets(bool udportcp,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort);
//     void parseUdpRawPackets(QVector<QByteArray>& payloadStorage,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort);
//     void parseTcpRawPackets(QVector<QByteArray>& payloadStorage,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort);

//     FragmentOutput parseUdpRawPacketFragment(const pcpp::RawPacket &rawPacket);

//     FragmentOutput parseTcpRawPacketFragment(const pcpp::RawPacket &rawPacket);
// };

// #endif // PCAPFILEFILTER_H
