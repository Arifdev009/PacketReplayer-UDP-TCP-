#include "udpsender.h"

UdpSender::UdpSender(QObject *parent) : QObject(parent), m_udpSocket(new QUdpSocket(this)) {
    // UDP sockets generally don't require explicit binding just to send data.
    // The OS will automatically pick an available local port for the outgoing packet.
}

UdpSender::~UdpSender() {
    m_udpSocket->close();
}

qint64 UdpSender::sendDatagram(const QByteArray &data, const QHostAddress &targetAddress, quint16 targetPort) {
    qint64 bytesWritten = m_udpSocket->writeDatagram(data, targetAddress, targetPort);

    if (bytesWritten == -1) {
        emit errorOccurred(m_udpSocket->errorString());
    }

    return bytesWritten;
}

qint64 UdpSender::sendDatagram(const QByteArray &data, const QString &targetHost, quint16 targetPort) {
    QHostAddress targetAddress(targetHost);
    return sendDatagram(data, targetAddress, targetPort);
}

qint64 UdpSender::broadcastDatagram(const QByteArray &data, quint16 targetPort) {
    // QHostAddress::Broadcast targets the global IPv4 broadcast address (255.255.255.255)
    return sendDatagram(data, QHostAddress::Broadcast, targetPort);
}
