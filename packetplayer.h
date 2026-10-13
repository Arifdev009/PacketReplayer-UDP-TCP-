#ifndef PACKETPLAYER_H
#define PACKETPLAYER_H

#include <QObject>
#include <QTimer>

#include "pcapfileFilter.h"
#include "tcpclient.h"
#include "udpsender.h"
#include "tcpserver.h"

enum PlayerStaus
{
    IDLEPLAYER,
    STARTPLAYER,
    STOPPLAYER,
    PAUSEPLAYER
    // RESUMEPLAYER
};

class packetPlayer: public QObject
{
    Q_OBJECT
public:
    packetPlayer(QObject *parent = nullptr);
    void initializeClassMembers();
    TcpClient *tcpclient;
    TcpServer *tcpserver;
    UdpSender *udpsender;

    QString socketSrcIP;
    QString socketDstIP;
    QString socketSrcPort;
    QString socketDstPort;

    void connectTcp(QHostAddress srcIpAddress,QHostAddress dstIpAddress,QString srcPort,QString dstPort);
    void startTcpServer(QHostAddress srcIpAddress,QHostAddress dstIpAddress,QString srcPort,QString dstPort);
    void connectUdp(QHostAddress srcIpAddress,QHostAddress dstIpAddress,QString srcPort,QString dstPort);
    void filterPcapFile(bool udportcp,unsigned int sendingudportcp,QString pcapFilePath,QSet<QString> srcIpAddress,QSet<QString> dstIpAddress,QSet<QString> srcPort,QSet<QString> dstPort);

    QVector<QByteArray> packetStorage;
    unsigned int sendudportcp = 0;
    QTimer *sendTimer;
    unsigned int packetIniIndex = 0;
    unsigned int packetFinalIndex = 0;
    unsigned int packetCurrentIndex = 0;
    int timerTimerout = 1000;

    QString udpTargetAddress;
    QString udpTargetport;
    unsigned int percentparced = 0;

    PlayerStaus enPlayerStatus;


signals:
    void tcpConnectionStatus(bool status);
    void tcpServerConnectionStatus(bool status);
    void packetsEnded(bool packetsend);
    void packetPercentageSent(unsigned int percent);

    void creatingUdpStatus(bool status);
    void creatingTcpStatus(bool status);
    void creatingTcpServerStatus(bool status);
    void parseFilterPcapFileStatus(bool status);

public slots:
    void playthePackets();
    void pausethePackets(bool pauseorResume);
    void startorstopthePackets(bool startorstop);
    void setCurrIndexwithSlider(unsigned int percent);
    void timerspeed(unsigned int timerSpeed);
};

#endif // PACKETPLAYER_H
