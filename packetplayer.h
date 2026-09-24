#ifndef PACKETPLAYER_H
#define PACKETPLAYER_H

#include <QObject>
#include <QTimer>

#include "pcapfileFilter.h"
#include "tcpclient.h"
#include "udpsender.h"


class packetPlayer: public QObject
{
    Q_OBJECT
public:
    packetPlayer(QObject *parent = nullptr);
    TcpClient *tcpclient;
    UdpSender *udpsender;
    bool connectTcp(QHostAddress dstIpAddress,QHostAddress srcIpAddress,QString srcPort,QString dstPort);
    bool connectUdp(QHostAddress dstIpAddress,QHostAddress srcIpAddress,QString srcPort,QString dstPort);
    bool filterPcapFile(bool udportcp,QString pcapFilePath,QString dstIpAddress,QString srcIpAddress,QString srcPort,QString dstPort);

    QVector<QByteArray> packetStorage;
    bool sendudportcp = 0;
    QTimer *sendTimer;
    unsigned int packetIniIndex = 0;
    unsigned int packetFinalIndex = 0;
    unsigned int packetCurrentIndex = 0;
    int timerTimerout = 1000;

    QString udpTargetAddress;
    QString udpTargetport;
    unsigned int percentparced = 0;

signals:
    void tcpConnectionStatus(bool status);
    void packetsEnded(bool packetsend);
    void packetPercentageSent(unsigned int percent);
public slots:
    void playthePackets();
    void pausethePackets(bool pauseorResume);
    void startorstopthePackets(bool startorstop);
    void setCurrIndexwithSlider(unsigned int percent);
    void timerspeed(unsigned int timerSpeed);
};

#endif // PACKETPLAYER_H
