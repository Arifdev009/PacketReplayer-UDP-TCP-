#include "packetplayer.h"

packetPlayer::packetPlayer(QObject *parent): QObject(parent)
{
    tcpclient = new TcpClient();
    udpsender = new UdpSender();

    sendTimer = new QTimer();
    connect(sendTimer,&QTimer::timeout,this,&packetPlayer::playthePackets);

    connect(tcpclient,&TcpClient::connectionStatusChanged,this,[=](bool isActive)
            {
                emit tcpConnectionStatus(isActive);
            });
}

bool packetPlayer::connectTcp(QHostAddress dstIpAddress, QHostAddress srcIpAddress, QString srcPort, QString dstPort)
{
    delete tcpclient;
    tcpclient = nullptr;
    tcpclient = new TcpClient();
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
        return false;
    }
    return true;
}

bool packetPlayer::connectUdp(QHostAddress dstIpAddress, QHostAddress srcIpAddress, QString srcPort, QString dstPort)
{
    delete udpsender;
    udpsender = nullptr;
    udpsender = new UdpSender();
    // udpsender->m_udpSocket.;
    if(!srcIpAddress.isNull() && !srcPort.isEmpty())
    {
        udpsender->m_udpSocket->bind(srcIpAddress,srcPort.toInt());
    }
    if(!dstIpAddress.isNull() && !dstPort.isEmpty())
    {
        // pcapFileFilter pcapfilefilter;
        // // packetStorage = pcapFileFilter::makeFilteredRawPackets();
        qDebug()<<"return true";
        return true;
        // tcpclient->connectToServer(dstIpAddress.toString(),dstPort.toInt());
    }
    else if(!dstPort.isEmpty())
    {
        qDebug()<<"return true";
        udpTargetAddress.clear();
        udpTargetport.clear();
        udpTargetAddress = dstIpAddress.toString();
        udpTargetport = dstPort;
        return true;
    }
    else
    {
        qDebug()<<"return false";
        return false;
    }
}

bool packetPlayer::filterPcapFile(bool udportcp,QString pcapFilePath, QString dstIpAddress, QString srcIpAddress, QString srcPort, QString dstPort)
{
    if(!pcapFilePath.isEmpty())
    {
        packetStorage.clear();

        pcapFileFilter pcapfilefilter;
        packetStorage = pcapfilefilter.makeFilteredRawPackets(udportcp,pcapFilePath,dstIpAddress,srcIpAddress,srcPort,dstPort);

        if(packetStorage.isEmpty())
        {
            return false;
        }
        else
        {
            packetIniIndex = 0;
            packetFinalIndex = packetStorage.size()-1;
            packetCurrentIndex = packetIniIndex;
            sendudportcp = udportcp;
            return true;
        }
    }
    else
    {
        return false;
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
            udpsender->broadcastDatagram(packetStorage[packetCurrentIndex],udpTargetport.toUShort());
            qDebug()<<"sending";        }
    }
    else if(sendudportcp == 1)
    {
        tcpclient->sendData(packetStorage[packetCurrentIndex]);
    }
    if(packetCurrentIndex<=packetFinalIndex)
    {
        qDebug()<<"index"<<packetCurrentIndex;
        packetCurrentIndex++;
        int temppercent = (100.0 * packetCurrentIndex) / packetFinalIndex;
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
        QMetaObject::invokeMethod(sendTimer, "stop", Qt::QueuedConnection);
    }
    else
    {

        QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
        // sendTimer->start(timerTimerout);
    }
}

void packetPlayer::startorstopthePackets(bool startorstop)
{
    if(startorstop)
    {
        percentparced =0;
        emit packetPercentageSent(percentparced);
        QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
        qDebug()<<"packets sent";

        // sendTimer->start(timerTimerout);
    }
    else
    {/*
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
    QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));

}

void packetPlayer::timerspeed(unsigned int timerSpeed)
{
    timerTimerout = 1000/timerSpeed;
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

    QMetaObject::invokeMethod(sendTimer, "start", Qt::QueuedConnection, Q_ARG(int, timerTimerout));
}
