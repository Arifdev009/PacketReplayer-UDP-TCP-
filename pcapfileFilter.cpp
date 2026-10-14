#include "pcapfileFilter.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <qdebug.h>

#include <QtEndian>


#include <QDebug>
#include <memory>
#include "IPv4Layer.h"
// #include "IPv6Layer.h"
// #include "UdpLayer.h"
#include "Packet.h"
#include "PcapFileDevice.h"
#include "IPReassembly.h"

// #include <QDebug>
// #include <memory>
#include <utility>
// #include "Packet.h"
// #include "PcapFileDevice.h"

#include <winsock2.h>

pcapFileFilter::pcapFileFilter(QObject *parent): QObject(parent)
{

}

QVector<QByteArray> pcapFileFilter::makeFilteredRawPackets(bool udportcp,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort)
{
    // QVector<QByteArray> packetStorage;
    QVector<QByteArray> payloadStorage;

    if(udportcp == 0)
    {
        parseUdpRawPackets(payloadStorage,filePath,srcIP,dstIP,srcPort,dstPort);
    }
    else if(udportcp == 1)
    {
        parseTcpRawPackets(payloadStorage,filePath,srcIP,dstIP,srcPort,dstPort);
    }

    for (const auto& payload : std::as_const(payloadStorage))
    {
        qDebug()<<"payload size : "<<payload.size();
    }


    return payloadStorage;

}







void pcapFileFilter::parseUdpRawPackets(QVector<QByteArray>& payloadStorage,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort)
{
    // 1. Open the PCAP file
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
    if (reader == nullptr || !reader->open())
    {
        qDebug() << "Error: Cannot open PCAP file at path:" << filePath;
        return;
    }

    // 2. Initialize the IP Reassembly Engine using its default clean constructor
    // (This avoids structural type mismatch collisions with lambda-to-function pointer conversions)
    pcpp::IPReassembly ipReassembly;
    pcpp::RawPacket rawPacket;

    // Lambda helper to process a fully unfragmented or successfully reassembled packet
    auto processPacket = [&](pcpp::Packet& packet)
    {
        if (!packet.isPacketOfType(pcpp::UDP) ||
            !(packet.isPacketOfType(pcpp::IPv4) || packet.isPacketOfType(pcpp::IPv6))) {
            return;
        }

        pcpp::UdpLayer* udpLayer = packet.getLayerOfType<pcpp::UdpLayer>();
        if (!udpLayer) return;

        QString currentSrcIP;
        QString currentDstIP;

        if (packet.isPacketOfType(pcpp::IPv4)) {
            pcpp::IPv4Layer* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
            if (ip4Layer) {
                currentSrcIP = QString::fromStdString(ip4Layer->getSrcIPv4Address().toString());
                currentDstIP = QString::fromStdString(ip4Layer->getDstIPv4Address().toString());
            }
        } else if (packet.isPacketOfType(pcpp::IPv6)) {
            pcpp::IPv6Layer* ip6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
            if (ip6Layer) {
                currentSrcIP = QString::fromStdString(ip6Layer->getSrcIPv6Address().toString());
                currentDstIP = QString::fromStdString(ip6Layer->getDstIPv6Address().toString());
            }
        }

        QString currentSrcPort = QString::number(ntohs(udpLayer->getUdpHeader()->portSrc));
        QString currentDstPort = QString::number(ntohs(udpLayer->getUdpHeader()->portDst));

        if (!srcIP.isEmpty() && !srcIP.contains(currentSrcIP)) return;
        if (!dstIP.isEmpty() && !dstIP.contains(currentDstIP)) return;
        if (!srcPort.isEmpty() && !srcPort.contains(currentSrcPort)) return;
        if (!dstPort.isEmpty() && !dstPort.contains(currentDstPort)) return;

        uint8_t* payloadData = udpLayer->getLayerPayload();
        size_t payloadLen = udpLayer->getLayerPayloadSize();

        if (payloadData && payloadLen > 0) {
            payloadStorage.append(QByteArray(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen)));
        }
    };

    // 3. Loop through all packets in the file
    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);
        pcpp::IPReassembly::ReassemblyStatus status;

        pcpp::Packet* reassembledPacket = ipReassembly.processPacket(&parsedPacket, status);

        if (status == pcpp::IPReassembly::REASSEMBLED && reassembledPacket != nullptr)
        {
            processPacket(*reassembledPacket);
            delete reassembledPacket; // Memory management requirement
        }
        else if (status == pcpp::IPReassembly::NON_FRAGMENT)
        {
            processPacket(parsedPacket);
        }
    }

    reader->close();
}


// struct sequenceAndPacket
// {
//     uint32_t sequenceNumber;
//     pcpp::Packet* packet;
//     bool pshFlag;
// };

struct fragmentedPacket
{
    QMap<uint32_t,QByteArray> fragmetedPackets;
    uint32_t lookingPacket;
    bool done;
};
//manually creating the ipReassemby
void pcapFileFilter::parseTcpRawPackets(QVector<QByteArray>& payloadStorage,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort)
{
    // 1. Open the PCAP file
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
    if (reader == nullptr || !reader->open())
    {
        qDebug() << "Error: Cannot open PCAP file at path:" << filePath;
        return;
    }


    // 2. Initialize the IP Reassembly Engine using its default clean constructor
    // (This avoids structural type mismatch collisions with lambda-to-function pointer conversions)
    pcpp::IPReassembly ipReassembly;
    pcpp::RawPacket rawPacket;


    QMap<uint32_t,pcpp::Packet> tempseqandrawPacketStorage;
    // QVector<sequenceAndPacket> tempseqandrawPacketStorage;
    // Lambda helper to process a fully unfragmented or successfully reassembled packet
    auto processPacket = [&](pcpp::Packet& packet)
    {
        if (!packet.isPacketOfType(pcpp::TCP) ||
            !(packet.isPacketOfType(pcpp::IPv4) || packet.isPacketOfType(pcpp::IPv6))) {
            return;
        }

        pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        if (!tcpLayer) return;

        QString currentSrcIP;
        QString currentDstIP;

        if (packet.isPacketOfType(pcpp::IPv4)) {
            pcpp::IPv4Layer* ip4Layer = packet.getLayerOfType<pcpp::IPv4Layer>();
            if (ip4Layer) {
                currentSrcIP = QString::fromStdString(ip4Layer->getSrcIPv4Address().toString());
                currentDstIP = QString::fromStdString(ip4Layer->getDstIPv4Address().toString());
            }
        } else if (packet.isPacketOfType(pcpp::IPv6)) {
            pcpp::IPv6Layer* ip6Layer = packet.getLayerOfType<pcpp::IPv6Layer>();
            if (ip6Layer) {
                currentSrcIP = QString::fromStdString(ip6Layer->getSrcIPv6Address().toString());
                currentDstIP = QString::fromStdString(ip6Layer->getDstIPv6Address().toString());
            }
        }

        pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();
        QString currentSrcPort = QString::number(ntohs(tcpLayer->getTcpHeader()->portSrc));
        QString currentDstPort = QString::number(ntohs(tcpLayer->getTcpHeader()->portDst));

        if (!srcIP.isEmpty() && !srcIP.contains(currentSrcIP)) return;
        if (!dstIP.isEmpty() && !dstIP.contains(currentDstIP)) return;
        if (!srcPort.isEmpty() && !srcPort.contains(currentSrcPort)) return;
        if (!dstPort.isEmpty() && !dstPort.contains(currentDstPort)) return;

        // sequenceAndPacket tempseqandpac;
        // tempseqandpac.sequenceNumber = ntohl(tcpHeader->sequenceNumber);
        // tempseqandpac.packet = &packet;
        // tempseqandpac.pshFlag = tcpHeader->pshFlag;
        tempseqandrawPacketStorage.insert(ntohl(tcpHeader->sequenceNumber),packet);


        // tcpHeader->sequenceNumber;

        uint8_t* payloadData = tcpLayer->getLayerPayload();
        size_t payloadLen = tcpLayer->getLayerPayloadSize();


        if (payloadData && payloadLen > 0) {
            // payloadStorage.append(QByteArray(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen)));
        }
    };

    // 3. Loop through all packets in the file
    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);
        pcpp::IPReassembly::ReassemblyStatus status;

        pcpp::Packet* reassembledPacket = ipReassembly.processPacket(&parsedPacket, status);

        if (status == pcpp::IPReassembly::REASSEMBLED && reassembledPacket != nullptr)
        {
            processPacket(*reassembledPacket);
            delete reassembledPacket; // Memory management requirement
        }
        else if (status == pcpp::IPReassembly::NON_FRAGMENT)
        {
            processPacket(parsedPacket);
        }
    }


    uint32_t isn = tempseqandrawPacketStorage.begin().key();
    for (auto i = tempseqandrawPacketStorage.begin();i != tempseqandrawPacketStorage.end();i++)
    {
        qDebug() << "Key:" << i.key()-isn;
    }



    QVector<MessageBlock> messageBlocks;
    MessageBlock currentBlock;

    // 2. Clear out the map step by step from the front
    while (!tempseqandrawPacketStorage.isEmpty())
    {
        auto it = tempseqandrawPacketStorage.begin();

        uint32_t currentSeq = it.key();

        // IMPORTANT: Grab a REFERENCE (&) so we don't trigger deep packet buffer copies
        pcpp::Packet& packet = it.value();

        pcpp::TcpLayer* tcpLayer = packet.getLayerOfType<pcpp::TcpLayer>();
        if (tcpLayer)
        {
            uint8_t* payloadData = tcpLayer->getLayerPayload();
            size_t payloadLen = tcpLayer->getLayerPayloadSize();

            if (payloadData && payloadLen > 0)
            {
                if (currentBlock.isFirstPacket) {
                    currentBlock.expectedNextSeq = currentSeq;
                    currentBlock.isFirstPacket = false;
                }

                // GAP DETECTION MATCH
                if (currentSeq > currentBlock.expectedNextSeq) {
                    currentBlock.hasHole = true;
                    messageBlocks.append(currentBlock);

                    currentBlock = MessageBlock();
                    currentBlock.expectedNextSeq = currentSeq;
                    currentBlock.isFirstPacket = false;
                }
                else if (currentSeq < currentBlock.expectedNextSeq) {
                    // Overlap mitigation
                    uint32_t overlap = currentBlock.expectedNextSeq - currentSeq;
                    if (overlap < payloadLen) {
                        payloadData += overlap;
                        payloadLen -= overlap;
                        currentBlock.buffer.append(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen));
                        currentBlock.expectedNextSeq = currentSeq + overlap + payloadLen;
                    }
                }
                else {
                    // Continuous data block tracking
                    currentBlock.buffer.append(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen));
                    currentBlock.expectedNextSeq = currentSeq + payloadLen;
                }

                // Read PSH Flag directly from the reference object
                pcpp::tcphdr* tcpHeader = tcpLayer->getTcpHeader();
                if (tcpHeader && tcpHeader->pshFlag == 1) {
                    messageBlocks.append(currentBlock);
                    currentBlock = MessageBlock();
                }
            }
        }

        // 3. Erase from map. This automatically destroys the pcpp::Packet object
        // and cleanly cleans up its allocated internal memory structures.
        tempseqandrawPacketStorage.erase(it);
    }

    // Flush any trailing elements
    if (!currentBlock.buffer.isEmpty()) {
        messageBlocks.append(currentBlock);
    }

    // 4. Finalizing Phase: Move pristine blocks to payloadStorage
    // ==========================================
    // THE FLUSHING PHASE: Filtering out the holes
    // ==========================================

    // Loop continuously while there are message blocks left in the vector
    while (!messageBlocks.isEmpty())
    {
        // 1. Reference the first message block in the queue
        const MessageBlock& block = messageBlocks.first();

        // 2. Evaluate if it contains a data hole
        if (block.hasHole)
        {
            std::cerr << "Dropping message block of size " << block.buffer.size()
            << " bytes due to data fragmentation holes." << std::endl;
        }
        else
        {
            // Pristine data block passes—append it to your main payload storage
            payloadStorage.append(block.buffer);
        }

        // 3. Delete the first item from the vector instantly.
        // This destroys the QByteArray buffer inside the block and frees up memory.
        messageBlocks.removeFirst();
    }

    reader->close();
}









// // #include <QDebug>
// // #include <memory>
// // #include <QHash>
// // #include "Packet.h"
// // #include "PcapFileDevice.h"
// // #include "TcpReassembly.h"

// // 1. Context Structure to manage filtering and streaming buffers
// struct TcpSmartAssemblyContext {
//     QVector<QByteArray>* finalStorage; // Target output container
//     QHash<uint32_t, QByteArray> streamBuffers; // Tracks active running assembly chunks per flowKey

//     const QSet<QString>* srcIP;
//     const QSet<QString>* dstIP;
//     const QSet<QString>* srcPort;
//     const QSet<QString>* dstPort;
// };

// // 2. The TCP Stream Callback
// /*static*/ void onTcpMessageReady(int8_t side, const pcpp::TcpStreamData& streamData, void* userCookie)
// {
//     if (!userCookie) return;

//     auto* context = static_cast<TcpSmartAssemblyContext*>(userCookie);
//     const pcpp::ConnectionData& connData = streamData.getConnectionData();

//     // Extract network details for filtering
//     QString currentSrcIP   = QString::fromStdString(connData.srcIP.toString());
//     QString currentDstIP   = QString::fromStdString(connData.dstIP.toString());
//     QString currentSrcPort = QString::number(connData.srcPort);
//     QString currentDstPort = QString::number(connData.dstPort);

//     // Apply user filters
//     // if (!context->srcIP->isEmpty() && !context->srcIP->contains(currentSrcIP)) return;
//     // if (!context->dstIP->isEmpty() && !context->dstIP->contains(currentDstIP)) return;
//     // if (!context->srcPort->isEmpty() && !context->srcPort->contains(currentSrcPort)) return;
//     // if (!context->dstPort->isEmpty() && !context->dstPort->contains(currentDstPort)) return;

//     const uint8_t* payloadData = streamData.getData();
//     size_t payloadLen = streamData.getDataLength();

//     if (payloadData && payloadLen > 0)
//     {
//         uint32_t streamKey = connData.flowKey;

//         // 1. Accumulate this block into our running assembly stream buffer

//         if (payloadLen < 1460)
//         {
//             QByteArray completedMessage = context->streamBuffers.take(streamKey);
//             if (!completedMessage.isEmpty())
//             {
//                 // This captures your 2808 byte sequences (1460 + 1348) perfectly!
//                 context->finalStorage->append(completedMessage);
//             }
//         }

//         context->streamBuffers[streamKey].append(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen));

//         // 2. SMART BOUNDARY CHECKING:
//         // PcapPlusPlus sets streamData.getDataLength() to a size smaller than standard
//         // MTU (or triggers flag states) when an application pushes an intentional flush boundary.
//         // If a packet was smaller than 1460, or it represents a completed block transaction,
//         // we can slice it here to avoid merging independent transactions together.

//         // Check if this segment represents the end of an application data unit burst
//         // (Typically marked when the arriving piece doesn't hit a maximum structural link limit,
//         // meaning it's the termination of a transmission burst).

//         // if (payloadLen < 1460)
//         // {
//         //     QByteArray completedMessage = context->streamBuffers.take(streamKey);
//         //     if (!completedMessage.isEmpty())
//         //     {
//         //         // This captures your 2808 byte sequences (1460 + 1348) perfectly!
//         //         context->finalStorage->append(completedMessage);
//         //     }
//         // }

//     }
// }

// // 3. Connection End Callback
// static void onTcpConnectionEnd(const pcpp::ConnectionData& connData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
// {
//     if (!userCookie) return;

//     auto* context = static_cast<TcpSmartAssemblyContext*>(userCookie);
//     uint32_t streamKey = connData.flowKey;

//     // If a connection closes via FIN/RST, flush out whatever is remaining in its buffer
//     if (context->streamBuffers.contains(streamKey))
//     {
//         QByteArray completedMessage = context->streamBuffers.take(streamKey);
//         if (!completedMessage.isEmpty())
//         {
//             context->finalStorage->append(completedMessage);
//         }
//     }
// }

// // 4. Main Entry Function
// void parseTcpRawPackets(QVector<QByteArray>& payloadStorage,
//                                         QString filePath,
//                                         QSet<QString> srcIP,
//                                         QSet<QString> dstIP,
//                                         QSet<QString> srcPort,
//                                         QSet<QString> dstPort)
// {
//     std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
//     if (reader == nullptr || !reader->open())
//     {
//         qDebug() << "Error: Cannot open PCAP file at path:" << filePath;
//         return;
//     }

//     TcpSmartAssemblyContext contextObj;
//     contextObj.finalStorage = &payloadStorage;
//     contextObj.srcIP        = &srcIP;
//     contextObj.dstIP        = &dstIP;
//     contextObj.srcPort      = &srcPort;
//     contextObj.dstPort      = &dstPort;

//     pcpp::TcpReassembly tcpReassembly(onTcpMessageReady, &contextObj, nullptr, onTcpConnectionEnd);
//     pcpp::RawPacket rawPacket;

//     while (reader->getNextPacket(rawPacket))
//     {
//         pcpp::Packet parsedPacket(&rawPacket);
//         tcpReassembly.reassemblePacket(parsedPacket);
//     }

//     // Force flush trailing internal bytes out to the callbacks
//     tcpReassembly.closeAllConnections();

//     // 5. EOF FINAL PURGE
//     // Empty out any trailing buffers that didn't hit a termination length check before EOF
//     if (!contextObj.streamBuffers.isEmpty())
//     {
//         for (auto it = contextObj.streamBuffers.begin(); it != contextObj.streamBuffers.end(); ++it)
//         {
//             if (!it.value().isEmpty())
//             {
//                 payloadStorage.append(it.value());
//             }
//         }
//         contextObj.streamBuffers.clear();
//     }

//     reader->close();
// }











































// // 1. Define a Context Structure to bridge the optional Qt filters into the static callback
// struct TcpFilterContext {
//     QVector<QByteArray>* storage;
//     const QSet<QString>* srcIP;
//     const QSet<QString>* dstIP;
//     const QSet<QString>* srcPort;
//     const QSet<QString>* dstPort;
// };

// // 2. The TCP Stream Callback
// // FIX: Added 'int8_t side' as the first parameter to match PcapPlusPlus callback signature requirement
// static void onTcpMessageReady(int8_t side, const pcpp::TcpStreamData& streamData, void* userCookie)
// {
//     if (!userCookie) return;

//     // Safely extract our filters and vector storage from the cookie context
//     auto* context = static_cast<TcpFilterContext*>(userCookie);

//     // Get metadata about the current TCP connection
//     const pcpp::ConnectionData& connData = streamData.getConnectionData();

//     // Extract network details for filtering
//     QString currentSrcIP   = QString::fromStdString(connData.srcIP.toString());
//     QString currentDstIP   = QString::fromStdString(connData.dstIP.toString());

//     // Pcpp::ConnectionData ports are already in host byte order
//     QString currentSrcPort = QString::number(connData.srcPort);
//     QString currentDstPort = QString::number(connData.dstPort);

//     // Apply the user's sets filters (Empty sets act as wildcards automatically)
//     if (!context->srcIP->isEmpty() && !context->srcIP->contains(currentSrcIP)) return;
//     if (!context->dstIP->isEmpty() && !context->dstIP->contains(currentDstIP)) return;
//     if (!context->srcPort->isEmpty() && !context->srcPort->contains(currentSrcPort)) return;
//     if (!context->dstPort->isEmpty() && !context->dstPort->contains(currentDstPort)) return;

//     // Extract raw payload data arriving on this segment
//     const uint8_t* payloadData = streamData.getData();
//     size_t payloadLen = streamData.getDataLength();

//     if (payloadData && payloadLen > 0)
//     {
//         context->storage->append(QByteArray(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen)));
//     }
// }

// // 3. The Main Entry Function
// void pcapFileFilter::parseTcpRawPackets(QVector<QByteArray>& payloadStorage,
//                                         QString filePath,
//                                         QSet<QString> srcIP,
//                                         QSet<QString> dstIP,
//                                         QSet<QString> srcPort,
//                                         QSet<QString> dstPort)
// {
//     // Open the PCAP file
//     std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
//     if (reader == nullptr || !reader->open())
//     {
//         qDebug() << "Error: Cannot open PCAP file at path:" << filePath;
//         return;
//     }

//     // Populate the context structural reference block
//     TcpFilterContext contextObj;
//     contextObj.storage = &payloadStorage;
//     contextObj.srcIP   = &srcIP;
//     contextObj.dstIP   = &dstIP;
//     contextObj.srcPort = &srcPort;
//     contextObj.dstPort = &dstPort;

//     // Initialize the TCP Reassembly Engine with our callback mechanism
//     pcpp::TcpReassembly tcpReassembly(onTcpMessageReady, &contextObj);
//     pcpp::RawPacket rawPacket;

//     // Stream loop processing
//     while (reader->getNextPacket(rawPacket))
//     {
//         pcpp::Packet parsedPacket(&rawPacket);

//         // FIX: Changed from processPacket to reassemblePacket to match API implementation
//         tcpReassembly.reassemblePacket(parsedPacket);
//     }

//     // Explicitly close all active open streams to flush out trailing bytes at EOF
//     tcpReassembly.closeAllConnections();

//     reader->close();
// }




// void pcapFileFilter::parseUdpRawPackets(QVector<QByteArray> payloadStorage, QString filePath, QSet<QString> srcIP, QSet<QString> dstIP, QSet<QString> srcPort, QSet<QString> dstPort)
// {
//     std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
//     if (reader == nullptr)
//     {
//         qDebug() << "Error: Cannot open PCAP file." ;
//         return;
//     }

//     if (!reader->open())
//     {
//         return;
//         qDebug() << "Error: Cannot open file at path:" << filePath;
//     }
//     pcpp::RawPacket rawPacket;
//     while (reader->getNextPacket(rawPacket))
//     {
//         pcpp::Packet parsedPacket(&rawPacket);
//         if (parsedPacket.isPacketOfType(pcpp::IPv4))
//         {
//             pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
//             if (ipLayer != nullptr)
//             {
//                 if (ipLayer->getIPv4Header()->protocol == 17)
//                 {

//                 }
//             }
//         }
//     }
// }



// void pcapFileFilter::parseTcpRawPackets(QVector<QByteArray>& payloadStorage, QString filePath, QSet<QString> srcIP, QSet<QString> dstIP, QSet<QString> srcPort, QSet<QString> dstPort)
// {

// }



// FragmentOutput pcapFileFilter::parseTcpRawPacketFragment(const pcpp::RawPacket &rawPacket)
// {
//     // qDebug()<<"TCP";
//     FragmentOutput output;

//     // Make a local, non-const copy of the raw packet to allow PcapPlusPlus layer parsing
//     pcpp::RawPacket packetCopy(rawPacket);
//     pcpp::Packet parsedPacket(&packetCopy);

//     // 1. Verify what layers are visible initially
//     pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
//     pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

//     // If it's not IPv4, or if it's an unfragmented packet that isn't TCP, drop it safely
//     if (!ipLayer || (!ipLayer->isFragment() && !tcpLayer))
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;
//         return output;
//     }

//     // --- CASE 1: Packet is NOT fragmented (Standard Single TCP Packet) ---
//     if (!ipLayer->isFragment())
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;

//         // Fetch the raw IP payload pointer and size
//         uint8_t* ipPayloadPtr = ipLayer->getLayerPayload();
//         size_t ipPayloadSize = ipLayer->getLayerPayloadSize();

//         if (ipPayloadPtr && ipPayloadSize >= 20) // Minimum TCP header size is 20 bytes
//         {
//             // Safely cast the pointer to the PcapPlusPlus TCP header structure
//             pcpp::tcphdr* tcpHeader = reinterpret_cast<pcpp::tcphdr*>(ipPayloadPtr);

//             // Calculate sizes based on the TCP Data Offset (words to bytes multiplier)
//             size_t tcpHeaderSize = tcpHeader->dataOffset * 4;

//             if (ipPayloadSize >= tcpHeaderSize)
//             {
//                 size_t actualDataSize = ipPayloadSize - tcpHeaderSize;
//                 uint8_t* tcpDataPtr = ipPayloadPtr + tcpHeaderSize;

//                 if (actualDataSize > 0) {
//                     output.payload = QByteArray(reinterpret_cast<const char*>(tcpDataPtr), static_cast<int>(actualDataSize));
//                 }
//             }
//         }
//         return output;
//     }
//     else
//     {
//         // qDebug() << "Fragmented packet detected.";
//     }

//     // --- CASE 2: Packet IS fragmented ---
//     output.isFragmented = true;
//     uint16_t fragOffset = ipLayer->getFragmentOffset();

//     uint8_t* payloadPtr = ipLayer->getLayerPayload();
//     size_t payloadSize = ipLayer->getLayerPayloadSize();

//     // Map out the Fragment Type Enum and handle TCP header stripping
//     if (ipLayer->isFirstFragment())
//     {
//         output.type = FIRST;
//         output.fragmentNumber = 1;

//         // FIX: Manually strip the TCP header from the FIRST fragment's payload
//         // PcapPlusPlus layers often won't register tcpLayer on fragments, so we parse manually
//         if (payloadPtr && payloadSize >= 20)
//         {
//             pcpp::tcphdr* tcpHeader = reinterpret_cast<pcpp::tcphdr*>(payloadPtr);
//             size_t tcpHeaderSize = tcpHeader->dataOffset * 4; // Convert words to bytes

//             if (payloadSize >= tcpHeaderSize)
//             {
//                 size_t actualDataSize = payloadSize - tcpHeaderSize;
//                 uint8_t* tcpDataPtr = payloadPtr + tcpHeaderSize;

//                 if (actualDataSize > 0) {
//                     output.payload = QByteArray(reinterpret_cast<const char*>(tcpDataPtr), static_cast<int>(actualDataSize));
//                 }
//             }
//         }
//     }
//     else // MIDDLE or LAST fragments
//     {
//         if (ipLayer->isLastFragment())
//         {
//             output.type = LAST;
//         }
//         else
//         {
//             output.type = MIDDLE;
//         }

//         // Calculate sequence order dynamically based on standard 8-byte boundary chunks
//         output.fragmentNumber = (fragOffset / 185) + 1;

//         // MIDDLE and LAST fragments contain ONLY raw data (no TCP headers exist here)
//         if (payloadPtr && payloadSize > 0)
//         {
//             output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
//         }
//     }

//     return output;
// }



// FragmentOutput pcapFileFilter::parseUdpRawPacketFragment(const pcpp::RawPacket &rawPacket)
// {
//     FragmentOutput output;

//     // Make a local, non-const copy of the raw packet to allow PcapPlusPlus layer parsing
//     pcpp::RawPacket packetCopy(rawPacket);
//     pcpp::Packet parsedPacket(&packetCopy);

//     // 1. Verify what layers are visible initially
//     pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
//     pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

//     // If it's not IPv4, or if it's an unfragmented packet that isn't UDP, drop it safely
//     if (!ipLayer || (!ipLayer->isFragment() && !udpLayer))
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;
//         return output;
//     }

//     // --- CASE 1: Packet is NOT fragmented (Standard Single UDP Packet) ---
//     if (!ipLayer->isFragment())
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;

//         // Fetch the raw IP payload pointer and size
//         uint8_t* ipPayloadPtr = ipLayer->getLayerPayload();
//         size_t ipPayloadSize = ipLayer->getLayerPayloadSize();

//         // A standard UDP header is always exactly 8 bytes
//         const size_t udpHeaderSize = 8;

//         if (ipPayloadPtr && ipPayloadSize > udpHeaderSize)
//         {
//             size_t actualDataSize = ipPayloadSize - udpHeaderSize;
//             uint8_t* udpDataPtr = ipPayloadPtr + udpHeaderSize;

//             if (actualDataSize > 0) {
//                 output.payload = QByteArray(reinterpret_cast<const char*>(udpDataPtr), static_cast<int>(actualDataSize));
//             }
//         }
//         return output;
//     }
//     else
//     {
//         // qDebug() << "Fragmented UDP packet detected.";
//     }

//     // --- CASE 2: Packet IS fragmented ---
//     output.isFragmented = true;
//     uint16_t fragOffset = ipLayer->getFragmentOffset();

//     uint8_t* payloadPtr = ipLayer->getLayerPayload();
//     size_t payloadSize = ipLayer->getLayerPayloadSize();

//     // Map out the Fragment Type Enum and handle UDP header stripping
//     if (ipLayer->isFirstFragment())
//     {
//         output.type = FIRST;
//         output.fragmentNumber = 1;

//         // Strip the 8-byte UDP header from the FIRST fragment's payload
//         const size_t udpHeaderSize = 8;

//         if (payloadPtr && payloadSize > udpHeaderSize)
//         {
//             size_t actualDataSize = payloadSize - udpHeaderSize;
//             uint8_t* udpDataPtr = payloadPtr + udpHeaderSize;

//             if (actualDataSize > 0) {
//                 output.payload = QByteArray(reinterpret_cast<const char*>(udpDataPtr), static_cast<int>(actualDataSize));
//             }
//         }
//     }
//     else // MIDDLE or LAST fragments
//     {
//         if (ipLayer->isLastFragment())
//         {
//             output.type = LAST;
//         }
//         else
//         {
//             output.type = MIDDLE;
//         }

//         // Calculate sequence order dynamically based on standard 8-byte boundary chunks
//         output.fragmentNumber = (fragOffset / 185) + 1;

//         // MIDDLE and LAST fragments contain ONLY raw data (no UDP headers exist here)
//         if (payloadPtr && payloadSize > 0)
//         {
//             output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
//         }
//     }

//     return output;
// }

// FragmentOutput pcapFileFilter::parseRawPacketFragment(const pcpp::RawPacket &rawPacket)
// {
//     FragmentOutput output;

//     // Make a local, non-const copy of the raw packet to allow PcapPlusPlus layer parsing
//     pcpp::RawPacket packetCopy(rawPacket);
//     pcpp::Packet parsedPacket(&packetCopy);

//     // 1. Verify this packet actually contains TCP data
//     pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
//     pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

//     // pcpp::iphdr* ipHeader = ipLayer->getIPv4Header();

//     // Print raw memory flags directly (using Qt's macro instead of pcpp::netToHost16)
//     // uint16_t rawOffsetAndFlags = qFromBigEndian(ipHeader->fragmentOffset);
//     // std::cout << "--- DIAGNOSTIC CHECK ---" << std::endl;
//     // std::cout << "Raw offset field in memory: 0x" << std::hex << rawOffsetAndFlags << std::dec << std::endl;
//     // std::cout << "Extracted Offset Value: " << ipLayer->getFragmentOffset() << std::endl;
//     // std::cout << "------------------------" << std::endl;



//     // If it's not IPv4, or if it's an unfragmented packet that isn't TCP, drop it safely
//     if (!ipLayer || (!ipLayer->isFragment() && !tcpLayer))
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;
//         return output;
//     }

//     // --- CASE 1: Packet is NOT fragmented (Standard Single TCP Packet) ---
//     if (!ipLayer->isFragment())
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;

//         // Fetch the raw IP payload pointer and size
//         uint8_t* ipPayloadPtr = ipLayer->getLayerPayload();
//         size_t ipPayloadSize = ipLayer->getLayerPayloadSize();

//         if (ipPayloadPtr && ipPayloadSize >= 20) // Minimum TCP header size is 20 bytes
//         {
//             // FIX: Safely cast the pointer to the PcapPlusPlus TCP header structure
//             pcpp::tcphdr* tcpHeader = reinterpret_cast<pcpp::tcphdr*>(ipPayloadPtr);

//             // Calculate sizes based on the TCP Data Offset (words to bytes multiplier)
//             size_t tcpHeaderSize = tcpHeader->dataOffset * 4;

//             if (ipPayloadSize >= tcpHeaderSize)
//             {
//                 size_t actualDataSize = ipPayloadSize - tcpHeaderSize;
//                 // qDebug() << "Total IP Payload Size (TCP Header + Data):" << ipPayloadSize;
//                 // qDebug() << "Actual TCP Data/Payload Size:" << actualDataSize;

//                 // Option A: If you want to store ONLY the actual application data (e.g., HTTP text, files)
//                 uint8_t* tcpDataPtr = ipPayloadPtr + tcpHeaderSize;
//                 if (actualDataSize > 0) {
//                     output.payload = QByteArray(reinterpret_cast<const char*>(tcpDataPtr), static_cast<int>(actualDataSize));
//                 }

//                 // Option B: If you actually wanted the whole TCP layer (Header + Data), uncomment the line below:
//                 // output.payload = QByteArray(reinterpret_cast<const char*>(ipPayloadPtr), static_cast<int>(ipPayloadSize));
//             }
//         }
//         return output;
//     }
//     else
//     {
//         qDebug()<<"Fragmented";
//     }

//     // --- CASE 2: Packet IS fragmented ---
//     output.isFragmented = true;
//     uint16_t fragOffset = ipLayer->getFragmentOffset();

//     // Map out the Fragment Type Enum
//     if (ipLayer->isFirstFragment())
//     {
//         output.type = FIRST;
//         output.fragmentNumber = 1;

//         // Note: For the FIRST fragment, tcpLayer will be valid!
//         // You could strip the TCP header here too if you only want raw app data.
//     }
//     else if (ipLayer->isLastFragment())
//     {
//         output.type = LAST;
//         output.fragmentNumber = (fragOffset / 185) + 1;
//     }
//     else
//     {
//         output.type = MIDDLE;
//         output.fragmentNumber = (fragOffset / 185) + 1;
//     }

//     // Extract the raw IP data payload bytes belonging specifically to this fragment
//     // Remember: MIDDLE and LAST fragments do NOT have a TCP header; they are just raw fragmented data.
//     uint8_t* payloadPtr = ipLayer->getLayerPayload();
//     size_t payloadSize = ipLayer->getLayerPayloadSize();
//     if (payloadPtr && payloadSize > 0)
//     {
//         output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
//     }

//     return output;
// }

// FragmentOutput pcapFileFilter::parseRawPacketFragment(const pcpp::RawPacket &rawPacket)
// {
//     FragmentOutput output;

//     // Make a local, non-const copy of the raw packet to allow PcapPlusPlus layer parsing
//     pcpp::RawPacket packetCopy(rawPacket);
//     pcpp::Packet parsedPacket(&packetCopy);

//     // Extract the IPv4 Layer
//     pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
//     if (!ipLayer)
//     {
//         // Handle non-IPv4 cases safely
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0;
//         return output;
//     }

//     // Check if the packet has its fragmentation bits or offset active
//     if (!ipLayer->isFragment())
//     {
//         output.isFragmented = false;
//         output.type = NOT_FRAGMENTED;
//         output.fragmentNumber = 0; // Unfragmented data behaves as a single unit (Index 0)

//         // Grab the unfragmented IP payload data anyway

//         uint8_t* payloadPtr = ipLayer->getLayerPayload();
//         size_t payloadSize = ipLayer->getLayerPayloadSize();
//         // qDebug()<<"payloadsize is "<<payloadSize;
//         if (payloadPtr && payloadSize > 0)
//         {
//             output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
//         }
//         return output;
//     }
//     else
//     {
//         qDebug()<<"Fragmented";
//     }

//     // --- Packet IS fragmented ---
//     output.isFragmented = true;
//     uint16_t fragOffset = ipLayer->getFragmentOffset();

//     // Map out the Fragment Type Enum
//     if (ipLayer->isFirstFragment())
//     {
//         output.type = FIRST;
//         output.fragmentNumber = 1; // The first fragment is always #1
//     }
//     else if (ipLayer->isLastFragment())
//     {
//         output.type = LAST;
//         // Calculate the fragment number based on its offset space
//         // Standard maximum payload size per fragment is 1480 bytes (offset step of 185)
//         output.fragmentNumber = (fragOffset / 185) + 1;
//     }
//     else
//     {
//         output.type = MIDDLE;
//         // Calculate sequence order dynamically based on the 8-byte boundary units
//         output.fragmentNumber = (fragOffset / 185) + 1;
//     }

//     // Extract the raw data payload bytes belonging specifically to this fragment
//     uint8_t* payloadPtr = ipLayer->getLayerPayload();
//     size_t payloadSize = ipLayer->getLayerPayloadSize();
//     if (payloadPtr && payloadSize > 0)
//     {
//         output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
//     }

//     return output;
// }


