#include "pcapfileparser.h"
#include <qdebug.h>

PcapFileParser::PcapFileParser(QObject *parent): QObject(parent)
{

}

void PcapFileParser::processFilePath(QString pcapFilePath)
{
    // Use the factory method to automatically detect and create the correct reader
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(pcapFilePath.toStdString()));

    // Check if the file format is supported or if the pointer is null
    if (!reader) {
        qDebug() << "Error: Unsupported file format or file does not exist.";
        return;
    }

    // Try to open the file
    if (!reader->open())
    {
        qDebug() << "Error: Cannot open the capture file.";
        return;
    }

    // Storage to keep track of unique communications and avoid duplicates

    QMap<QString, QSet<QString>>  mapUdpIptoIP;
    QMap<QString, QSet<QString>>  mapUdpPorttoPort;
    QMap<QString, QSet<QString>>  mapUdpIpcomboSrcPort;
    QMap<QString, QSet<QString>>  mapUdpIpSrcPortComboDstCombo;


    QMap<QString, QSet<QString>>  mapTcpIptoIP;
    QMap<QString, QSet<QString>>  mapTcpPorttoPort;
    QMap<QString, QSet<QString>>  mapTcpIpcomboSrcPort;
    QMap<QString, QSet<QString>>  mapTcpIpSrcPortComboDstCombo;

    pcpp::RawPacket rawPacket;

    bool hasUdpPackets = false;
    bool hasTcpPackets = false;
    // 2. Read packet by packet
    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);

        QString srcIP = "";
        QString dstIP = "";
        QString srcPort = "";
        QString dstPort = "";
        bool hasIP = false;
        bool hasPort = false;

        // Extract TCP Ports
        if (parsedPacket.isPacketOfType(pcpp::TCP))
        {
            hasTcpPackets = true;
            pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            srcPort = QString::number(tcpLayer->getSrcPort());
            dstPort = QString::number(tcpLayer->getDstPort());
            hasPort = true;

            // Extract IPv4 addresses
            if (parsedPacket.isPacketOfType(pcpp::IPv4))
            {
                pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
                srcIP = QString::fromStdString(ipLayer->getSrcIPv4Address().toString());
                dstIP = QString::fromStdString(ipLayer->getDstIPv4Address().toString());
                hasIP = true;
            }
            // Extract IPv6 addresses
            else if (parsedPacket.isPacketOfType(pcpp::IPv6))
            {
                pcpp::IPv6Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
                srcIP = QString::fromStdString(ipLayer->getSrcIPv6Address().toString());
                dstIP = QString::fromStdString(ipLayer->getDstIPv6Address().toString());
                hasIP = true;
            }
            if (hasIP && hasPort)
            {
                mapTcpIptoIP[srcIP].insert(dstIP);
                mapTcpPorttoPort[srcPort].insert(dstPort);
                mapTcpIpcomboSrcPort[srcIP+"\t"+dstIP].insert(srcPort);
                mapTcpIpSrcPortComboDstCombo[srcIP+"\t"+dstIP+"\t"+srcPort].insert(dstPort);
            }
        }
        else if (parsedPacket.isPacketOfType(pcpp::UDP))
        {
            hasUdpPackets = true;
            pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
            srcPort = QString::number(udpLayer->getSrcPort());
            dstPort = QString::number(udpLayer->getDstPort());
            hasPort = true;
            // Extract IPv4 addresses
            if (parsedPacket.isPacketOfType(pcpp::IPv4))
            {
                pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
                srcIP = QString::fromStdString(ipLayer->getSrcIPv4Address().toString());
                dstIP = QString::fromStdString(ipLayer->getDstIPv4Address().toString());
                hasIP = true;
            }
            // Extract IPv6 addresses
            else if (parsedPacket.isPacketOfType(pcpp::IPv6))
            {
                pcpp::IPv6Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();
                srcIP = QString::fromStdString(ipLayer->getSrcIPv6Address().toString());
                dstIP = QString::fromStdString(ipLayer->getDstIPv6Address().toString());
                hasIP = true;
            }
            if (hasIP && hasPort)
            {
                mapUdpIptoIP[srcIP].insert(dstIP);
                mapUdpPorttoPort[srcPort].insert(dstPort);
                mapUdpIpcomboSrcPort[srcIP+"\t"+dstIP].insert(srcPort);
                mapUdpIpSrcPortComboDstCombo[srcIP+"\t"+dstIP+"\t"+srcPort].insert(dstPort);
            }
        }
    }

    emit udportcpExists(hasUdpPackets,hasTcpPackets);
    if(hasUdpPackets)
    {
        emit udpList(mapUdpIptoIP,mapUdpPorttoPort,mapUdpIpcomboSrcPort,mapUdpIpSrcPortComboDstCombo);
    }
    if(hasTcpPackets)
    {
        emit tcpList(mapTcpIptoIP,mapTcpPorttoPort,mapTcpIpcomboSrcPort,mapTcpIpSrcPortComboDstCombo);
    }

    // QMap<QString, QSet<QString>> networkData;

    // Loop through every IP and its set of protocols
    for (const auto [ipAddress, protocolSet] : mapTcpIptoIP.asKeyValueRange()) {
        qDebug() << "IP Address:" << ipAddress;

        // Nested loop to read the inner QSet
        for (const QString &protocol : protocolSet)
        {
            qDebug() << "  -> Protocol:" << protocol;
        }
    }

    qDebug() << "DONE";
    // Loop through every IP and its set of protocols
    for (const auto [ipAddress, protocolSet] : mapTcpPorttoPort.asKeyValueRange()) {
        qDebug() << "IP Address:" << ipAddress;

        // Nested loop to read the inner QSet
        for (const QString &protocol : protocolSet)
        {
            qDebug() << "  -> Protocol:" << protocol;
        }
    }
qDebug() << "DONE";
    // Loop through every IP and its set of protocols
    for (const auto [ipAddress, protocolSet] : mapTcpIpcomboSrcPort.asKeyValueRange()) {
        qDebug() << "IP Address:" << ipAddress;

        // Nested loop to read the inner QSet
        for (const QString &protocol : protocolSet)
        {
            qDebug() << "  -> Protocol:" << protocol;
        }
    }
    qDebug() << "DONE";

    // Loop through every IP and its set of protocols
    for (const auto [ipAddress, protocolSet] : mapTcpIpSrcPortComboDstCombo.asKeyValueRange()) {
        qDebug() << "IP Address:" << ipAddress;

        // Nested loop to read the inner QSet
        for (const QString &protocol : protocolSet)
        {
            qDebug() << "  -> Protocol:" << protocol;
        }
    }


    reader->close();

}
