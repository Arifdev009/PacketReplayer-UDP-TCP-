#ifndef PCAPFILEFILTER_H
#define PCAPFILEFILTER_H

#include <QObject>
#include <iostream>
#include "PcapFileDevice.h"
#include "PcapFilter.h"

class pcapFileFilter : public QObject
{
    Q_OBJECT
public:
    pcapFileFilter(QObject *parent = nullptr);
    QVector<QByteArray> makeFilteredRawPackets(bool udportcp,QString filePath,QString srcIP,QString dstIP,QString srcPort,QString dstPort);
};

#endif // PCAPFILEFILTER_H
