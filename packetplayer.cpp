#include "packetplayer.h"

packetPlayer::packetPlayer(QObject *parent): QObject(parent)
{

}

void packetPlayer::initializeClassMembers()
{
    tcpclient = new TcpClient();
    udpsender = new UdpSender();
    tcpserver = new TcpServer();
    sendTimer = new QTimer();
    connect(sendTimer,&QTimer::timeout,this,&packetPlayer::playthePackets);

    connect(tcpclient,&TcpClient::connectionStatusChanged,this,[=](bool isActive)
            {
                startorstopthePackets(false);
                emit tcpConnectionStatus(isActive);
            });
    connect(tcpserver,&TcpServer::connectionStatusChanged,this,[=](bool isActive)
            {
                startorstopthePackets(false);
                emit tcpServerConnectionStatus(isActive);
            });
    enPlayerStatus = IDLEPLAYER;
}

void packetPlayer::connectTcp(QHostAddress srcIpAddress, QHostAddress dstIpAddress, QString srcPort, QString dstPort)
{

    if(srcIpAddress.toString() == socketSrcIP && srcPort == socketSrcPort && dstIpAddress.toString() == socketDstIP && dstPort == socketDstPort )
    {
        if(tcpclient->isConnected())
        {
            emit tcpConnectionStatus(true);
        }
        // return true;
    }
    else
    {
        socketSrcIP = srcIpAddress.toString();
        socketDstIP = dstIpAddress.toString();
        socketSrcPort = srcPort;
        socketDstPort = dstPort;

        tcpclient->disconnectFromServer();
        delete tcpclient;
        tcpclient = nullptr;
        tcpclient = new TcpClient();

        connect(tcpclient,&TcpClient::connectionStatusChanged,this,[=](bool isActive)
                {
                    emit tcpConnectionStatus(isActive);
                });
        if(!srcIpAddress.isNull() && !srcPort.isEmpty())
        {
            tcpclient->m_socket->bind(srcIpAddress,srcPort.toInt());
        }
        if(!dstIpAddress.isNull() && !dstPort.isEmpty())
        {
            tcpclient->connectToServer(dstIpAddress.toString(),dstPort.toInt());
        }
        else
        {
            emit creatingTcpStatus(false);
            // return false;
        }
        emit creatingTcpStatus(true);
    }
}

void packetPlayer::startTcpServer(QHostAddress srcIpAddress, QHostAddress dstIpAddress, QString srcPort, QString dstPort)
{
    if(srcIpAddress.toString() == socketSrcIP && srcPort == socketSrcPort && dstIpAddress.toString() == socketDstIP && dstPort == socketDstPort )
    {
        if(tcpserver->noofClientsinServer() > 0)
        {
            emit tcpServerConnectionStatus(true);
        }
    }
    else
    {
        socketSrcIP = srcIpAddress.toString();
        socketDstIP = dstIpAddress.toString();
        socketSrcPort = srcPort;
        socketDstPort = dstPort;

        tcpserver->stopServer();
        delete tcpserver;
        tcpserver = nullptr;
        tcpserver = new TcpServer();

        connect(tcpserver,&TcpServer::connectionStatusChanged,this,[=](bool isActive)
                {
                    emit tcpServerConnectionStatus(isActive);
                });
        if(!srcPort.isEmpty())
        {
            tcpserver->startServer(srcPort.toUShort());
            if(tcpserver != nullptr)
            {
                emit creatingTcpServerStatus(true);
            }
            else
            {
                emit creatingTcpServerStatus(false);
            }
        }
        else
        {

        }
    }
}

void packetPlayer::connectUdp(QHostAddress srcIpAddress, QHostAddress dstIpAddress, QString srcPort, QString dstPort)
{
    // delete udpsender;
    // udpsender = nullptr;
    // if(udpsender == nullptr)
    // {
    //     qDebug()<<"deleted the udpsender";
    // }

    // udpsender = new UdpSender();
    // if(udpsender != nullptr)
    // {
    //     qDebug()<<"created the udpsender";
    // }
    // udpsender->m_udpSocket.;
    if(srcIpAddress.toString() == socketSrcIP && srcPort == socketSrcPort && dstIpAddress.toString() == socketDstIP && dstPort == socketDstPort )
    {
        qDebug()<<"different file";
        if(udpsender->m_udpSocket != nullptr)
        {
            emit creatingUdpStatus(true);
        }

        // return true;
    }
    else
    {
        socketSrcIP = srcIpAddress.toString();
        socketDstIP = dstIpAddress.toString();
        socketSrcPort = srcPort;
        socketDstPort = dstPort;

        udpsender->disconnect();
        delete udpsender;
        udpsender = nullptr;
        udpsender = new UdpSender();

        if(!srcIpAddress.isNull() && !srcPort.isEmpty())
        {
            udpsender->m_udpSocket->bind(srcIpAddress,srcPort.toInt());
        }
        if(!dstIpAddress.isNull() && !dstPort.isEmpty())
        {
            udpTargetAddress.clear();
            udpTargetport.clear();
            udpTargetAddress = dstIpAddress.toString();
            udpTargetport = dstPort;
            // pcapFileFilter pcapfilefilter;
            // // packetStorage = pcapFileFilter::makeFilteredRawPackets();
            qDebug()<<"return true";
            emit creatingUdpStatus(true);
            // tcpclient->connectToServer(dstIpAddress.toString(),dstPort.toInt());
        }
        else if(!dstPort.isEmpty())
        {
            qDebug()<<"return true";
            udpTargetAddress.clear();
            udpTargetport.clear();
            // udpTargetAddress = dstIpAddress.toString();
            udpTargetport = dstPort;
            if(udpsender->m_udpSocket->isOpen())
            {
                qDebug()<<"udp sender is open";
            }
            emit creatingUdpStatus(true);
        }
        else
        {
            qDebug()<<"return false";
            emit creatingUdpStatus(false);
        }
    }

}

void packetPlayer::filterPcapFile(bool udportcp,unsigned int sendingudportcp,QString pcapFilePath, QSet<QString> srcIpAddress, QSet<QString> dstIpAddress, QSet<QString> srcPort, QSet<QString> dstPort)
{
    if(!pcapFilePath.isEmpty())
    {
        packetStorage.clear();

        pcapFileFilter pcapfilefilter;
        packetStorage = pcapfilefilter.makeFilteredRawPackets(udportcp,pcapFilePath,srcIpAddress,dstIpAddress,srcPort,dstPort);

        if(packetStorage.isEmpty())
        {
            emit parseFilterPcapFileStatus(false);
            // return false;
        }
        else
        {
            packetIniIndex = 0;
            packetFinalIndex = packetStorage.size()-1;
            packetCurrentIndex = packetIniIndex;
            sendudportcp = sendingudportcp;
            emit parseFilterPcapFileStatus(true);
        }
    }
    else
    {
        emit parseFilterPcapFileStatus(true);
    }
}

void packetPlayer::playthePackets()
{
    qDebug()<<"intheplaytheplaythepackets";
    if(sendudportcp == 0)
    {
        if(!udpTargetport.isEmpty() && !udpTargetAddress.isEmpty())
        {
            udpsender->sendDatagram(packetStorage[packetCurrentIndex],udpTargetAddress,udpTargetport.toUShort());
        }
        else
        {
            qDebug()<<packetStorage[packetCurrentIndex].size();
            udpsender->broadcastDatagram(packetStorage[packetCurrentIndex],udpTargetport.toUShort());
            qDebug()<<"sending";
        }
    }
    else if(sendudportcp == 1)
    {
        tcpclient->sendData(packetStorage[packetCurrentIndex]);
    }
    else if(sendudportcp == 2)
    {
        tcpserver->broadcastData(packetStorage[packetCurrentIndex]);
    }

    if(packetCurrentIndex<=packetFinalIndex)
    {
        qDebug()<<"index"<<packetCurrentIndex;
        packetCurrentIndex++;
        unsigned int temppercent = (100.0 * packetCurrentIndex) / packetFinalIndex;
        qDebug()<<"percentparced"<<percentparced;
        if(temppercent > percentparced)
        {
            percentparced = temppercent;
            emit packetPercentageSent(percentparced);
        }

        if(packetCurrentIndex>packetFinalIndex)
        {
            emit packetPercentageSent(100);
            emit packetsEnded(false);
            startorstopthePackets(false);
        }
    }


}

void packetPlayer::pausethePackets(bool pauseorResume)
{
    if(pauseorResume == true)
    {
        enPlayerStatus = PAUSEPLAYER;
        QMetaObject::invokeMethod(sendTimer, "stop", Qt::QueuedConnection);
    }
    else
    {
        enPlayerStatus = STARTPLAYER;
        QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
        // sendTimer->start(timerTimerout);
    }
}

void packetPlayer::startorstopthePackets(bool startorstop)
{
    if(startorstop)
    {
        enPlayerStatus = STARTPLAYER;
        percentparced =0;
        emit packetPercentageSent(percentparced);
        QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
        qDebug()<<"packets sent";

        // sendTimer->start(timerTimerout);
    }
    else
    {
        enPlayerStatus = STOPPLAYER;
        /*
        percentparced =0;
        emit packetPercentageSent(percentparced);*/
        packetCurrentIndex = 0;
        emit packetPercentageSent(percentparced);
        QMetaObject::invokeMethod(sendTimer, "stop", Qt::QueuedConnection);
        qDebug()<<"packets sent";
        // sendTimer->stop();
    }
}

void packetPlayer::setCurrIndexwithSlider(unsigned int percent)
{

    QMetaObject::invokeMethod(sendTimer, "stop", Qt::QueuedConnection);
    percentparced = percent;
    packetCurrentIndex = ((percent/100.0)*packetFinalIndex);
    if(enPlayerStatus == STARTPLAYER)
    {
        QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
    }
}

void packetPlayer::timerspeed(unsigned int timerSpeed)
{
    timerTimerout = 1000.0/timerSpeed;
    if(sendTimer->isActive())
    {
        QMetaObject::invokeMethod(sendTimer, "stop", Qt::QueuedConnection);
        QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
        // QMetaObject::invokeMethod(sendTimer, "setInterval", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
    }
    // QMetaObject::invokeMethod(sendTimer, "stop", Qt::QueuedConnection);
    // sendTimer->stop();
    // String-based alternative
    // QMetaObject::invokeMethod(sendTimer, "setInterval", Qt::QueuedConnection, Q_ARG(int, timerTimerout));

    // QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
}
