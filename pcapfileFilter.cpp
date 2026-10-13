#include "pcapfileFilter.h"
#include "PcapFileDevice.h"
#include "IPv4Layer.h"
#include "IPv6Layer.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include "TcpReassembly.h"
#include "RawPacket.h"
#include "Packet.h"

#include <QtEndian>
#include <QDebug>
#include <map>
#include <memory>

#include<IPReassembly.h>
#include<winsock2.h>

// ============================================================================
// INTERNAL PRIVATE STRUCTURES & CONFIGURATIONS FOR TCP REASSEMBLY
// ============================================================================
struct TcpStreamContext {
    QByteArray streamBuffer;
    bool meetsFilterCriteria = false;
};

struct StreamSlicingState {
    enum FrameType { UNKNOWN, BINARY_BE32, BINARY_LE32, BINARY_BE16, BINARY_LE16, TEXT_LINE };
    FrameType detectedType = UNKNOWN;
    int bytesNeeded = 0;
};

struct ReassemblyFilters {
    QSet<QString> srcIP;
    QSet<QString> dstIP;
    QSet<QString> srcPort;
    QSet<QString> dstPort;
    std::map<uint32_t, TcpStreamContext> connectionManager;
};

// Global/Static tracking variables for callback identification
static std::map<uint32_t, StreamSlicingState> globalStreamTracker;
static uint32_t currentActiveFlowKey = 0;

// ============================================================================
// PCAPPLUSPLUS TCP REASSEMBLY ENGINE CALLBACKS
// ============================================================================
void tcpReassemblyMsgReadyCallback(int side, const pcpp::TcpStreamData& streamData, void* userCookie)
{
    auto* filtersObj = static_cast<ReassemblyFilters*>(userCookie);
    uint32_t flowKey = streamData.getConnectionData().flowKey;

    if (filtersObj->connectionManager.find(flowKey) == filtersObj->connectionManager.end()) {
        return;
    }

    TcpStreamContext& ctx = filtersObj->connectionManager[flowKey];
    if (!ctx.meetsFilterCriteria) {
        return;
    }

    if (streamData.getDataLength() > 0) {
        ctx.streamBuffer.append(reinterpret_cast<const char*>(streamData.getData()), static_cast<int>(streamData.getDataLength()));
    }
}

void tcpReassemblyConnectionStartCallback(const pcpp::ConnectionData& connectionData, void* userCookie)
{
    auto* filtersObj = static_cast<ReassemblyFilters*>(userCookie);

    QString currentSrcIP = QString::fromStdString(connectionData.srcIP.toString());
    QString currentDstIP = QString::fromStdString(connectionData.dstIP.toString());
    QString currentSrcPort = QString::number(connectionData.srcPort);
    QString currentDstPort = QString::number(connectionData.dstPort);

    bool match = true;
    if (!filtersObj->srcIP.isEmpty() && !filtersObj->srcIP.contains(currentSrcIP)) match = false;
    if (!filtersObj->dstIP.isEmpty() && !filtersObj->dstIP.contains(currentDstIP)) match = false;
    if (!filtersObj->srcPort.isEmpty() && !filtersObj->srcPort.contains(currentSrcPort)) match = false;
    if (!filtersObj->dstPort.isEmpty() && !filtersObj->dstPort.contains(currentDstPort)) match = false;

    TcpStreamContext newContext;
    newContext.meetsFilterCriteria = match;
    filtersObj->connectionManager[connectionData.flowKey] = newContext;
}

void tcpReassemblyConnectionEndCallback(const pcpp::ConnectionData& connectionData, pcpp::TcpReassembly::ConnectionEndReason reason, void* userCookie)
{
    auto* filtersObj = static_cast<ReassemblyFilters*>(userCookie);
    filtersObj->connectionManager.erase(connectionData.flowKey);
    globalStreamTracker.erase(connectionData.flowKey);
}

// ============================================================================
// CLASS IMPLEMENTATIONS
// ============================================================================
// pcapFileFilter::pcapFileFilter(QObject *parent) : QObject(parent)
// {
// }

QVector<QByteArray> pcapFileFilter::makeFilteredRawPackets(bool udportcp, QString filePath, QSet<QString> srcIP, QSet<QString> dstIP, QSet<QString> srcPort, QSet<QString> dstPort)
{
    QVector<QByteArray> payloadStorage;

    if (udportcp == false) // 0 = UDP
    {
        parseUdpRawPackets(payloadStorage, filePath, srcIP, dstIP, srcPort, dstPort);
    }
    else if (udportcp == true) // 1 = TCP
    {
        // UNIVERSAL ROBUST USER-UPLOADED PCAP AUTO-DETECTION ENGINE
        MessageLengthDecoder universalPredictor = [](const QByteArray& buffer) -> int {
            if (buffer.isEmpty()) return 0;

            StreamSlicingState& state = globalStreamTracker[currentActiveFlowKey];
            const int MAX_SANE_MESSAGE_SIZE = 10 * 1024 * 1024; // 10MB Threshold limit

            if (state.detectedType != StreamSlicingState::UNKNOWN && state.bytesNeeded > 0) {
                if (buffer.size() < state.bytesNeeded) return 0;
                int totalFrameLen = state.bytesNeeded;
                state.detectedType = StreamSlicingState::UNKNOWN;
                state.bytesNeeded = 0;
                return totalFrameLen;
            }

            if (buffer.at(0) == '\x00') {
                return 1; // Safely consume 1 null byte at a time to keep scanning for headers
            }


            char firstByte = buffer.at(0);
            if ((firstByte >= 'A' && firstByte <= 'Z') || (firstByte >= 'a' && firstByte <= 'z') || firstByte == '{' || firstByte == '[') {
                int newlinePos = buffer.indexOf('\n');
                if (newlinePos != -1) return newlinePos + 1;
                if (buffer.size() > 8192) return buffer.size();
                return 0;
            }

            if (buffer.size() < 4) return 0;

            quint32 len32BE = qFromBigEndian<quint32>(reinterpret_cast<const uchar*>(buffer.constData()));
            quint32 len32LE = qFromLittleEndian<quint32>(reinterpret_cast<const uchar*>(buffer.constData()));
            quint16 len16BE = qFromBigEndian<quint16>(reinterpret_cast<const uchar*>(buffer.constData()));
            quint16 len16LE = qFromLittleEndian<quint16>(reinterpret_cast<const uchar*>(buffer.constData()));

            if (len32BE > 0 && (4 + (int)len32BE) <= MAX_SANE_MESSAGE_SIZE) {
                state.detectedType = StreamSlicingState::BINARY_BE32;
                state.bytesNeeded = 4 + len32BE;
                if (buffer.size() >= state.bytesNeeded) {
                    state.detectedType = StreamSlicingState::UNKNOWN;
                    state.bytesNeeded = 0;
                    return 4 + len32BE;
                }
                return 0;
            }

            if (len32LE > 0 && (4 + (int)len32LE) <= MAX_SANE_MESSAGE_SIZE) {
                state.detectedType = StreamSlicingState::BINARY_LE32;
                state.bytesNeeded = 4 + len32LE;
                if (buffer.size() >= state.bytesNeeded) {
                    state.detectedType = StreamSlicingState::UNKNOWN;
                    state.bytesNeeded = 0;
                    return 4 + len32LE;
                }
                return 0;
            }

            if (len16BE > 0 && (2 + (int)len16BE) < 65535) return 2 + len16BE;
            if (len16LE > 0 && (2 + (int)len16LE) < 65535) return 2 + len16LE;

            return buffer.size(); // Fallback for raw, unhandled binary streams
        };

        parseTcpRawPackets(payloadStorage, filePath, srcIP, dstIP, srcPort, dstPort, universalPredictor);
    }

    for(int i=0;i<payloadStorage.size();i++)
    {
        qDebug()<<"packet size:"<<payloadStorage[0].size();
    }
    return payloadStorage;
}

void pcapFileFilter::parseTcpRawPackets(QVector<QByteArray>& payloadStorage,
                                        QString filePath,
                                        QSet<QString> srcIP,
                                        QSet<QString> dstIP,
                                        QSet<QString> srcPort,
                                        QSet<QString> dstPort,
                                        MessageLengthDecoder lengthDecoder)
{
    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
    if (reader == nullptr || !reader->open()) {
        qDebug() << "Error: Cannot open PCAP file at path:" << filePath;
        return;
    }

    // Flush volatile system trackers to keep processing instances clean between execution intervals
    globalStreamTracker.clear();
    currentActiveFlowKey = 0;

    ReassemblyFilters dynamicFilters;
    dynamicFilters.srcIP = srcIP;
    dynamicFilters.dstIP = dstIP;
    dynamicFilters.srcPort = srcPort;
    dynamicFilters.dstPort = dstPort;

    pcpp::TcpReassembly tcpReassembly(tcpReassemblyMsgReadyCallback, &dynamicFilters,
                                      tcpReassemblyConnectionStartCallback, tcpReassemblyConnectionEndCallback);

    pcpp::RawPacket rawPacket;

    while (reader->getNextPacket(rawPacket))
    {
        pcpp::Packet parsedPacket(&rawPacket);
        if (parsedPacket.isPacketOfType(pcpp::TCP))
        {
            // Extract properties to assign flow context
            pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
            if (tcpLayer) {
                // Calculate dynamic tracking flow key matching internal PcapPlusPlus properties
                // This lets us assign contextual stream variables inside the loop window natively
                pcpp::IPv4Layer* ip4 = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();
                pcpp::IPv6Layer* ip6 = parsedPacket.getLayerOfType<pcpp::IPv6Layer>();

                // Let the engine process the packet first to register/update connections
                tcpReassembly.reassemblePacket(&rawPacket);

                // Run slicing operations iteratively over active monitored buffers
                for (auto& [flowKey, context] : dynamicFilters.connectionManager)
                {
                    if (!context.meetsFilterCriteria) continue;

                    // Set global context identifier for our current decoder access
                    currentActiveFlowKey = flowKey;

                    while (!context.streamBuffer.isEmpty())
                    {
                        int messageLength = lengthDecoder(context.streamBuffer);
                        if (messageLength <= 0 || context.streamBuffer.size() < messageLength) {
                            break;
                        }
                        QByteArray fullApplicationMessage = context.streamBuffer.left(messageLength);
                        payloadStorage.append(fullApplicationMessage);
                        context.streamBuffer.remove(0, messageLength);
                    }
                }
            }
        }
    }
    tcpReassembly.closeAllConnections();
    reader->close();
}


pcapFileFilter::pcapFileFilter(QObject *parent): QObject(parent)
{

}

// QVector<QByteArray> pcapFileFilter::makeFilteredRawPackets(bool udportcp,QString filePath,QSet<QString> srcIP,QSet<QString> dstIP,QSet<QString> srcPort,QSet<QString> dstPort)
// {
//     // QVector<QByteArray> packetStorage;
//     QVector<QByteArray> payloadStorage;





//     if(udportcp == 0)
//     {
//         parseUdpRawPackets(payloadStorage,filePath,srcIP,dstIP,srcPort,dstPort);
//     }
//     else if(udportcp == 1)
//     {


//         // Call function
//         QVector<QByteArray> messages;
//         //  CORRECT
//         parseTcpRawPackets(payloadStorage, filePath, srcIP, dstIP, srcPort, dstPort, myDecoder);


//         // parseTcpRawPackets(payloadStorage,filePath,srcIP,dstIP,srcPort,dstPort);
//     }

//     for (const auto& payload : std::as_const(payloadStorage))
//     {
//         qDebug()<<"payload size : "<<payload.size();
//     }


//     return payloadStorage;
//     // std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::tryCreateReader(filePath.toStdString()));
//     // if (reader == nullptr)
//     // {
//     //     qDebug() << "Error: Cannot open PCAP file." ;
//     //     return payloadStorage;
//     //     // return 1;
//     // }

//     // if (!reader->open())
//     // {
//     //     qDebug() << "Error: Cannot open file at path:" << filePath;
//     //     return payloadStorage;
//     // }


//     // // 1. Notice the 'udp' keyword at the start of the string
//     // QString bpfExpression;
//     // if(udportcp == 0)
//     // {
//     //     bpfExpression = "udp or (ip[6:2] & 0x3fff != 0)";
//     // }
//     // else if(udportcp == 1)
//     // {
//     //     bpfExpression = "tcp ";
//     // }

//     // if(!bpfExpression.isEmpty())
//     // {
//     //     if(!srcIP.isEmpty())
//     //     {
//     //         bpfExpression = bpfExpression +" and src host "+srcIP;
//     //     }
//     // }
//     // else
//     // {
//     //     if(!srcIP.isEmpty())
//     //     {
//     //         bpfExpression = "src host "+srcIP;
//     //     }
//     // }

//     // if(!bpfExpression.isEmpty())
//     // {
//     //     if(!srcPort.isEmpty())
//     //     {
//     //         bpfExpression = bpfExpression +" and src port "+srcPort;
//     //     }
//     // }
//     // else
//     // {
//     //     if(!srcPort.isEmpty())
//     //     {
//     //         bpfExpression = "src port "+srcPort;
//     //     }
//     // }

//     // if(!bpfExpression.isEmpty())
//     // {
//     //     if(!dstIP.isEmpty())
//     //     {
//     //         bpfExpression = bpfExpression +" and dst host "+dstIP;
//     //     }
//     // }
//     // else
//     // {
//     //     if(!dstIP.isEmpty())
//     //     {
//     //         bpfExpression = "dst host "+dstIP;
//     //     }
//     // }

//     // if(!bpfExpression.isEmpty())
//     // {
//     //     if(!dstPort.isEmpty())
//     //     {
//     //         bpfExpression = bpfExpression +" and dst port "+dstPort;
//     //     }
//     // }
//     // else
//     // {
//     //     if(!dstPort.isEmpty())
//     //     {
//     //         bpfExpression = "dst port "+dstPort;
//     //     }
//     // }


//     // Change this line:
//     // pcpp::BPFStringFilter filter(bpfExpression.toStdString());

//     // if (!reader->setFilter(filter)) {
//     //     std::cerr << "Error: Invalid BpfFilter expression." << std::endl;
//     //     // return; // Fix: use 'return;' instead of 'return 1;' for void function
//     // }


//     // // qDebug() << "Filtering UDP packets matching: " << bpfExpression;

//     // pcpp::RawPacket rawPacket;
//     // int matchCount = 0;

//     // QVector<QByteArray> tempFragmentedPayload;
//     // while (reader->getNextPacket(rawPacket)) {
//     //     matchCount++;

//     //     // 1. Get the pointer to the raw data and its length
//     //     const uint8_t* rawDataPtr = rawPacket.getRawData();
//     //     int rawDataLen = rawPacket.getRawDataLen();

//     //     if (rawDataPtr != nullptr && rawDataLen > 0)
//     //     {
//     //         // 2. Convert the raw bytes into a QByteArray and push it to the QVector
//     //         // The QByteArray constructor deeply copies the memory buffer


//     //         FragmentOutput result;

//     //         if(udportcp == 0)
//     //         {
//     //             result = parseUdpRawPacketFragment(rawPacket);
//     //         }
//     //         else if(udportcp ==1)
//     //         {
//     //             result = parseTcpRawPacketFragment(rawPacket);
//     //         }


//     //         if (result.isFragmented)
//     //         {
//     //             // qDebug()<<"Fragmented";
//     //             // std::cout << "Fragment Number: #" << result.fragmentNumber << "\n";

//     //             if(result.type == FIRST)
//     //             {
//     //                 tempFragmentedPayload.clear();
//     //                 tempFragmentedPayload.push_back(result.payload);
//     //                 // std::cout << "Type: FIRST\n";
//     //             }
//     //             else if(result.type == MIDDLE)
//     //             {
//     //                 if(tempFragmentedPayload.size()<result.fragmentNumber){tempFragmentedPayload.resize(result.fragmentNumber);}
//     //                 tempFragmentedPayload[result.fragmentNumber-1] = result.payload;
//     //                 // std::cout << "Type: MIDDLE\n";
//     //             }
//     //             else if(result.type == LAST)
//     //             {

//     //                 int totalSize = 0;
//     //                 QByteArray combined;
//     //                 tempFragmentedPayload.push_back(result.payload);

//     //                 for (const QByteArray &ba : std::as_const(tempFragmentedPayload))
//     //                 {
//     //                     totalSize += ba.size();
//     //                 }
//     //                 combined.reserve(totalSize);

//     //                 // Append each QByteArray into the single result
//     //                 for (const QByteArray &ba : std::as_const(tempFragmentedPayload))
//     //                 {
//     //                     combined.append(ba);
//     //                 }
//     //                 payloadStorage.append(combined);
//     //                 tempFragmentedPayload.clear();
//     //                 // std::cout << "Type: LAST\n";
//     //                 std::cout << "Payload Size: " << combined.size() << " bytes\n";

//     //             }
//     //         }
//     //         else
//     //         {
//     //             tempFragmentedPayload.clear();
//     //             // std::cout << "Payload Size: " << result.payload.size() << " bytes\n";
//     //             payloadStorage.append(result.payload);
//     //         }

//     //         // packetStorage.append(QByteArray(reinterpret_cast<const char*>(rawDataPtr), rawDataLen));
//     //     }

//     // timespec ts = rawPacket.getPacketTimeStamp();
//     // qDebug() << "[" << matchCount << "] Matched UDP packet at: "
//     //          << ts.tv_sec << "." << ts.tv_nsec << " ("
//     //          << rawDataLen << " bytes stored)" ;
//     // }

//     // qDebug() << "\nTotal matched UDP packets: " << matchCount;

//     // reader->close();
//     // return payloadStorage;

// }







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
// static void onTcpMessageReady(int8_t side, const pcpp::TcpStreamData& streamData, void* userCookie)
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
//     if (!context->srcIP->isEmpty() && !context->srcIP->contains(currentSrcIP)) return;
//     if (!context->dstIP->isEmpty() && !context->dstIP->contains(currentDstIP)) return;
//     if (!context->srcPort->isEmpty() && !context->srcPort->contains(currentSrcPort)) return;
//     if (!context->dstPort->isEmpty() && !context->dstPort->contains(currentDstPort)) return;

//     const uint8_t* payloadData = streamData.getData();
//     size_t payloadLen = streamData.getDataLength();

//     if (payloadData && payloadLen > 0)
//     {
//         uint32_t streamKey = connData.flowKey;

//         // 1. Accumulate this block into our running assembly stream buffer
//         context->streamBuffers[streamKey].append(reinterpret_cast<const char*>(payloadData), static_cast<int>(payloadLen));

//         // 2. SMART BOUNDARY CHECKING:
//         // PcapPlusPlus sets streamData.getDataLength() to a size smaller than standard
//         // MTU (or triggers flag states) when an application pushes an intentional flush boundary.
//         // If a packet was smaller than 1460, or it represents a completed block transaction,
//         // we can slice it here to avoid merging independent transactions together.

//         // Check if this segment represents the end of an application data unit burst
//         // (Typically marked when the arriving piece doesn't hit a maximum structural link limit,
//         // meaning it's the termination of a transmission burst).
//         if (payloadLen < 1460)
//         {
//             QByteArray completedMessage = context->streamBuffers.take(streamKey);
//             if (!completedMessage.isEmpty())
//             {
//                 // This captures your 2808 byte sequences (1460 + 1348) perfectly!
//                 context->finalStorage->append(completedMessage);
//             }
//         }
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
// void pcapFileFilter::parseTcpRawPackets(QVector<QByteArray>& payloadStorage,
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

