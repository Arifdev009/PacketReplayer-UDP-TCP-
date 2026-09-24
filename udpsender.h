#ifndef UDPSENDER_H
#define UDPSENDER_H

#include <QObject>
#include <QUdpSocket>
#include <QHostAddress>

class UdpSender : public QObject {
    Q_OBJECT
public:
    explicit UdpSender(QObject *parent = nullptr);
    ~UdpSender();

    // Sends data to a specific target IP and port
    qint64 sendDatagram(const QByteArray &data, const QHostAddress &targetAddress, quint16 targetPort);

    // Helper to send data using a string IP representation
    qint64 sendDatagram(const QByteArray &data, const QString &targetHost, quint16 targetPort);

    // Broadcasts data to the entire local network
    qint64 broadcastDatagram(const QByteArray &data, quint16 targetPort);

signals:
    void errorOccurred(const QString &errorStr);

public:
    QUdpSocket *m_udpSocket;
};
#endif // UDPSENDER_H
