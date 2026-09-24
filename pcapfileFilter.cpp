#include "pcapfileFilter.h"
#include <qdebug.h>

pcapFileFilter::pcapFileFilter(QObject *parent): QObject(parent)
{

}

QVector<QByteArray> pcapFileFilter::makeFilteredRawPackets(bool udportcp,QString filePath,QString srcIP,QString dstIP,QString srcPort,QString dstPort)
{
    QVector<QByteArray> packetStorage;
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(filePath.toStdString()));
    if (reader == nullptr)
    {
        qDebug() << "Error: Cannot open PCAP file." ;
        return packetStorage;
        // return 1;
    }

    if (!reader->open())
    {
        qDebug() << "Error: Cannot open file at path:" << filePath;
        return packetStorage;
    }


    // 1. Notice the 'udp' keyword at the start of the string
    QString bpfExpression;
    if(udportcp == 0)
    {
        bpfExpression = "udp ";
    }
    else if(udportcp == 1)
    {
        bpfExpression = "tcp ";
    }

    if(!bpfExpression.isEmpty())
    {
        if(!srcIP.isEmpty())
        {
            bpfExpression = bpfExpression +" and src host "+srcIP;
        }
    }
    else
    {
        if(!srcIP.isEmpty())
        {
            bpfExpression = "src host "+srcIP;
        }
    }

    if(!bpfExpression.isEmpty())
    {
        if(!srcPort.isEmpty())
        {
            bpfExpression = bpfExpression +" and src port "+srcPort;
        }
    }
    else
    {
        if(!srcPort.isEmpty())
        {
            bpfExpression = "src port "+srcPort;
        }
    }

    if(!bpfExpression.isEmpty())
    {
        if(!dstIP.isEmpty())
        {
            bpfExpression = bpfExpression +" and dst host "+dstIP;
        }
    }
    else
    {
        if(!dstIP.isEmpty())
        {
            bpfExpression = "dst host "+dstIP;
        }
    }

    if(!bpfExpression.isEmpty())
    {
        if(!dstPort.isEmpty())
        {
            bpfExpression = bpfExpression +" and dst port "+dstPort;
        }
    }
    else
    {
        if(!dstPort.isEmpty())
        {
            bpfExpression = "dst port "+dstPort;
        }
    }


    // Change this line:
    pcpp::BPFStringFilter filter(bpfExpression.toStdString());

    if (!reader->setFilter(filter)) {
        std::cerr << "Error: Invalid BpfFilter expression." << std::endl;
        // return; // Fix: use 'return;' instead of 'return 1;' for void function
    }


    qDebug() << "Filtering UDP packets matching: " << bpfExpression;

    pcpp::RawPacket rawPacket;
    int matchCount = 0;

    while (reader->getNextPacket(rawPacket)) {
        matchCount++;

        // 1. Get the pointer to the raw data and its length
        const uint8_t* rawDataPtr = rawPacket.getRawData();
        int rawDataLen = rawPacket.getRawDataLen();

        if (rawDataPtr != nullptr && rawDataLen > 0) {
            // 2. Convert the raw bytes into a QByteArray and push it to the QVector
            // The QByteArray constructor deeply copies the memory buffer
            packetStorage.append(QByteArray(reinterpret_cast<const char*>(rawDataPtr), rawDataLen));
        }

        timespec ts = rawPacket.getPacketTimeStamp();
        qDebug() << "[" << matchCount << "] Matched UDP packet at: "
                  << ts.tv_sec << "." << ts.tv_nsec << " ("
                  << rawDataLen << " bytes stored)" ;
    }

    qDebug() << "\nTotal matched UDP packets: " << matchCount;

    reader->close();
    return packetStorage;

}
