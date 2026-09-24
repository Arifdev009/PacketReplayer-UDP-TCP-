#ifndef PCAPFILEPARSER_H
#define PCAPFILEPARSER_H

#include<QObject>

// PcapPlusPlus Parsing Libraries
#include <PcapFileDevice.h>
#include <Packet.h>
#include <TcpLayer.h>
#include <PayloadLayer.h>


#include "PcapFileDevice.h"
#include "Packet.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <QDebug>
#include <QMap>


class PcapFileParser : public QObject
{
    Q_OBJECT
public:
    PcapFileParser(QObject *parent = nullptr);
    void processFilePath(QString pcapFilePath);
signals:
    void udportcpExists(bool udpExists,bool TcpExists);
    void udpList(QMap<QString, QSet<QString>>  mapUdpIptoIP,QMap<QString, QSet<QString>>  mapUdpPorttoPort,QMap<QString, QSet<QString>>  mapUdpIpcomboSrcPort,QMap<QString, QSet<QString>>  mapUdpIpSrcPortComboDstCombo);
    void tcpList(QMap<QString, QSet<QString>>  mapTcpIptoIP,QMap<QString, QSet<QString>>  mapTcpPorttoPort,QMap<QString, QSet<QString>>  mapTcpIpcomboSrcPort,QMap<QString, QSet<QString>>  mapTcpIpSrcPortComboDstCombo);
};

#endif // PCAPFILEPARSER_H
