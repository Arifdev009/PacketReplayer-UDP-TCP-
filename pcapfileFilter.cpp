#include "pcapfileFilter.h"
#include "TcpLayer.h"
#include "UdpLayer.h"
#include <qdebug.h>

#include <QtEndian>


pcapFileFilter::pcapFileFilter(QObject *parent): QObject(parent)
{

}

QVector<QByteArray> pcapFileFilter::makeFilteredRawPackets(bool udportcp,QString filePath,QString srcIP,QString dstIP,QString srcPort,QString dstPort)
{
    // QVector<QByteArray> packetStorage;
    QVector<QByteArray> payloadStorage;

    std::unique_ptr<pcpp::IFileReaderDevice> reader(pcpp::IFileReaderDevice::getReader(filePath.toStdString()));
    if (reader == nullptr)
    {
        qDebug() << "Error: Cannot open PCAP file." ;
        return payloadStorage;
        // return 1;
    }

    if (!reader->open())
    {
        qDebug() << "Error: Cannot open file at path:" << filePath;
        return payloadStorage;
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


    // qDebug() << "Filtering UDP packets matching: " << bpfExpression;

    pcpp::RawPacket rawPacket;
    int matchCount = 0;

    QVector<QByteArray> tempFragmentedPayload;
    while (reader->getNextPacket(rawPacket)) {
        matchCount++;

        // 1. Get the pointer to the raw data and its length
        const uint8_t* rawDataPtr = rawPacket.getRawData();
        int rawDataLen = rawPacket.getRawDataLen();

        if (rawDataPtr != nullptr && rawDataLen > 0)
        {
            // 2. Convert the raw bytes into a QByteArray and push it to the QVector
            // The QByteArray constructor deeply copies the memory buffer


            FragmentOutput result;

            if(udportcp == 0)
            {
                result = parseUdpRawPacketFragment(rawPacket);
            }
            else if(udportcp ==1)
            {
                result = parseTcpRawPacketFragment(rawPacket);
            }


            if (result.isFragmented)
            {
                // qDebug()<<"Fragmented";
                // std::cout << "Fragment Number: #" << result.fragmentNumber << "\n";

                if(result.type == FIRST)
                {
                    tempFragmentedPayload.clear();
                    tempFragmentedPayload.push_back(result.payload);
                    // std::cout << "Type: FIRST\n";
                }
                else if(result.type == MIDDLE)
                {
                    if(tempFragmentedPayload.size()<result.fragmentNumber){tempFragmentedPayload.resize(result.fragmentNumber);}
                    tempFragmentedPayload[result.fragmentNumber-1] = result.payload;
                    // std::cout << "Type: MIDDLE\n";
                }
                else if(result.type == LAST)
                {

                    int totalSize = 0;
                    QByteArray combined;
                    tempFragmentedPayload.push_back(result.payload);

                    for (const QByteArray &ba : std::as_const(tempFragmentedPayload))
                    {
                        totalSize += ba.size();
                    }
                    combined.reserve(totalSize);

                    // Append each QByteArray into the single result
                    for (const QByteArray &ba : std::as_const(tempFragmentedPayload))
                    {
                        combined.append(ba);
                    }
                    payloadStorage.append(combined);
                    tempFragmentedPayload.clear();
                    // std::cout << "Type: LAST\n";
                    std::cout << "Payload Size: " << combined.size() << " bytes\n";

                }
            }
            else
            {
                tempFragmentedPayload.clear();
                // std::cout << "Payload Size: " << result.payload.size() << " bytes\n";
                payloadStorage.append(result.payload);
            }

            // packetStorage.append(QByteArray(reinterpret_cast<const char*>(rawDataPtr), rawDataLen));
        }

        // timespec ts = rawPacket.getPacketTimeStamp();
        // qDebug() << "[" << matchCount << "] Matched UDP packet at: "
        //          << ts.tv_sec << "." << ts.tv_nsec << " ("
        //          << rawDataLen << " bytes stored)" ;
    }

    // qDebug() << "\nTotal matched UDP packets: " << matchCount;

    reader->close();
    return payloadStorage;

}



FragmentOutput pcapFileFilter::parseTcpRawPacketFragment(const pcpp::RawPacket &rawPacket)
{
    // qDebug()<<"TCP";
    FragmentOutput output;

    // Make a local, non-const copy of the raw packet to allow PcapPlusPlus layer parsing
    pcpp::RawPacket packetCopy(rawPacket);
    pcpp::Packet parsedPacket(&packetCopy);

    // 1. Verify what layers are visible initially
    pcpp::TcpLayer* tcpLayer = parsedPacket.getLayerOfType<pcpp::TcpLayer>();
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    // If it's not IPv4, or if it's an unfragmented packet that isn't TCP, drop it safely
    if (!ipLayer || (!ipLayer->isFragment() && !tcpLayer))
    {
        output.isFragmented = false;
        output.type = NOT_FRAGMENTED;
        output.fragmentNumber = 0;
        return output;
    }

    // --- CASE 1: Packet is NOT fragmented (Standard Single TCP Packet) ---
    if (!ipLayer->isFragment())
    {
        output.isFragmented = false;
        output.type = NOT_FRAGMENTED;
        output.fragmentNumber = 0;

        // Fetch the raw IP payload pointer and size
        uint8_t* ipPayloadPtr = ipLayer->getLayerPayload();
        size_t ipPayloadSize = ipLayer->getLayerPayloadSize();

        if (ipPayloadPtr && ipPayloadSize >= 20) // Minimum TCP header size is 20 bytes
        {
            // Safely cast the pointer to the PcapPlusPlus TCP header structure
            pcpp::tcphdr* tcpHeader = reinterpret_cast<pcpp::tcphdr*>(ipPayloadPtr);

            // Calculate sizes based on the TCP Data Offset (words to bytes multiplier)
            size_t tcpHeaderSize = tcpHeader->dataOffset * 4;

            if (ipPayloadSize >= tcpHeaderSize)
            {
                size_t actualDataSize = ipPayloadSize - tcpHeaderSize;
                uint8_t* tcpDataPtr = ipPayloadPtr + tcpHeaderSize;

                if (actualDataSize > 0) {
                    output.payload = QByteArray(reinterpret_cast<const char*>(tcpDataPtr), static_cast<int>(actualDataSize));
                }
            }
        }
        return output;
    }
    else
    {
        // qDebug() << "Fragmented packet detected.";
    }

    // --- CASE 2: Packet IS fragmented ---
    output.isFragmented = true;
    uint16_t fragOffset = ipLayer->getFragmentOffset();

    uint8_t* payloadPtr = ipLayer->getLayerPayload();
    size_t payloadSize = ipLayer->getLayerPayloadSize();

    // Map out the Fragment Type Enum and handle TCP header stripping
    if (ipLayer->isFirstFragment())
    {
        output.type = FIRST;
        output.fragmentNumber = 1;

        // FIX: Manually strip the TCP header from the FIRST fragment's payload
        // PcapPlusPlus layers often won't register tcpLayer on fragments, so we parse manually
        if (payloadPtr && payloadSize >= 20)
        {
            pcpp::tcphdr* tcpHeader = reinterpret_cast<pcpp::tcphdr*>(payloadPtr);
            size_t tcpHeaderSize = tcpHeader->dataOffset * 4; // Convert words to bytes

            if (payloadSize >= tcpHeaderSize)
            {
                size_t actualDataSize = payloadSize - tcpHeaderSize;
                uint8_t* tcpDataPtr = payloadPtr + tcpHeaderSize;

                if (actualDataSize > 0) {
                    output.payload = QByteArray(reinterpret_cast<const char*>(tcpDataPtr), static_cast<int>(actualDataSize));
                }
            }
        }
    }
    else // MIDDLE or LAST fragments
    {
        if (ipLayer->isLastFragment())
        {
            output.type = LAST;
        }
        else
        {
            output.type = MIDDLE;
        }

        // Calculate sequence order dynamically based on standard 8-byte boundary chunks
        output.fragmentNumber = (fragOffset / 185) + 1;

        // MIDDLE and LAST fragments contain ONLY raw data (no TCP headers exist here)
        if (payloadPtr && payloadSize > 0)
        {
            output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
        }
    }

    return output;
}



FragmentOutput pcapFileFilter::parseUdpRawPacketFragment(const pcpp::RawPacket &rawPacket)
{
    FragmentOutput output;

    // Make a local, non-const copy of the raw packet to allow PcapPlusPlus layer parsing
    pcpp::RawPacket packetCopy(rawPacket);
    pcpp::Packet parsedPacket(&packetCopy);

    // 1. Verify what layers are visible initially
    pcpp::UdpLayer* udpLayer = parsedPacket.getLayerOfType<pcpp::UdpLayer>();
    pcpp::IPv4Layer* ipLayer = parsedPacket.getLayerOfType<pcpp::IPv4Layer>();

    // If it's not IPv4, or if it's an unfragmented packet that isn't UDP, drop it safely
    if (!ipLayer || (!ipLayer->isFragment() && !udpLayer))
    {
        output.isFragmented = false;
        output.type = NOT_FRAGMENTED;
        output.fragmentNumber = 0;
        return output;
    }

    // --- CASE 1: Packet is NOT fragmented (Standard Single UDP Packet) ---
    if (!ipLayer->isFragment())
    {
        output.isFragmented = false;
        output.type = NOT_FRAGMENTED;
        output.fragmentNumber = 0;

        // Fetch the raw IP payload pointer and size
        uint8_t* ipPayloadPtr = ipLayer->getLayerPayload();
        size_t ipPayloadSize = ipLayer->getLayerPayloadSize();

        // A standard UDP header is always exactly 8 bytes
        const size_t udpHeaderSize = 8;

        if (ipPayloadPtr && ipPayloadSize > udpHeaderSize)
        {
            size_t actualDataSize = ipPayloadSize - udpHeaderSize;
            uint8_t* udpDataPtr = ipPayloadPtr + udpHeaderSize;

            if (actualDataSize > 0) {
                output.payload = QByteArray(reinterpret_cast<const char*>(udpDataPtr), static_cast<int>(actualDataSize));
            }
        }
        return output;
    }
    else
    {
        // qDebug() << "Fragmented UDP packet detected.";
    }

    // --- CASE 2: Packet IS fragmented ---
    output.isFragmented = true;
    uint16_t fragOffset = ipLayer->getFragmentOffset();

    uint8_t* payloadPtr = ipLayer->getLayerPayload();
    size_t payloadSize = ipLayer->getLayerPayloadSize();

    // Map out the Fragment Type Enum and handle UDP header stripping
    if (ipLayer->isFirstFragment())
    {
        output.type = FIRST;
        output.fragmentNumber = 1;

        // Strip the 8-byte UDP header from the FIRST fragment's payload
        const size_t udpHeaderSize = 8;

        if (payloadPtr && payloadSize > udpHeaderSize)
        {
            size_t actualDataSize = payloadSize - udpHeaderSize;
            uint8_t* udpDataPtr = payloadPtr + udpHeaderSize;

            if (actualDataSize > 0) {
                output.payload = QByteArray(reinterpret_cast<const char*>(udpDataPtr), static_cast<int>(actualDataSize));
            }
        }
    }
    else // MIDDLE or LAST fragments
    {
        if (ipLayer->isLastFragment())
        {
            output.type = LAST;
        }
        else
        {
            output.type = MIDDLE;
        }

        // Calculate sequence order dynamically based on standard 8-byte boundary chunks
        output.fragmentNumber = (fragOffset / 185) + 1;

        // MIDDLE and LAST fragments contain ONLY raw data (no UDP headers exist here)
        if (payloadPtr && payloadSize > 0)
        {
            output.payload = QByteArray(reinterpret_cast<const char*>(payloadPtr), static_cast<int>(payloadSize));
        }
    }

    return output;
}

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


