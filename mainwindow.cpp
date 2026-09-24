#include "mainwindow.h"
#include "ui_mainwindow.h"



MainWindow::MainWindow(QWidget *parent)
    : QMainWindow(parent)
    , ui(new Ui::MainWindow)
{
    ui->setupUi(this);


    const QList<QHostAddress> ipAddressesList = QNetworkInterface::allAddresses();

    // Loop through the addresses to find a valid local IPv4 address
    for (const QHostAddress &address : ipAddressesList) {
        // Filter out loopback (127.0.0.1) and ensure it is IPv4
        if (address != QHostAddress::LocalHost && address.toIPv4Address())
        {
            ui->userIPComboBox->addItem(address.toString());
            qDebug() << "Current Local IPv4 Address:" << address.toString();
            // Optional: break; if you only want the first active one found
        }
    }

    QIntValidator *validator = new QIntValidator(0, 65535, this);

    // 3. Assign the validator to the LineEdit
    ui->srcPortLineEdit->setValidator(validator);
    ui->dstPortlineEdit->setValidator(validator);

    ui->playUDPorTCPComboBox->addItem("UDP");
    ui->playUDPorTCPComboBox->addItem("TCP");

    packetplayer = new packetPlayer;
    packetplayerThread = new QThread(this);
    packetplayer->moveToThread(packetplayerThread);
    packetplayerThread->start();

    connect(packetplayer,&packetPlayer::tcpConnectionStatus,this,&MainWindow::tcpConnectionStatus);
    connect(packetplayer,&packetPlayer::packetsEnded,this,&MainWindow::on_playPushButton_clicked);
    connect(packetplayer,&packetPlayer::packetPercentageSent,this,
            [=](int percent)
            {
                ui->playerProgressBar->setValue(percent);
            });

    pcapfileparser = new PcapFileParser;
    pcapFileParserThread = new QThread(this);
    pcapfileparser->moveToThread(pcapFileParserThread);
    pcapFileParserThread->start();
    ui->udporTcpComboBox->setPlaceholderText("select UDP or TCP");


    ui->filteringComboBox->setPlaceholderText("select Filter");
    ui->filteringComboBox->addItem("Port");
    ui->filteringComboBox->addItem("IP Address");
    ui->filteringComboBox->addItem("Both");

    ui->filteringComboBox->setEnabled(false);
    ui->udporTcpComboBox->setEnabled(false);

    ui->srcIpListWidget->setEnabled(false);
    ui->dstIpListWidget->setEnabled(false);

    ui->srcPortListWidget->setEnabled(false);
    ui->dstPortListWidget->setEnabled(false);

    ui->srcIpListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->dstIpListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->srcPortListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
    ui->dstPortListWidget->setSelectionMode(QAbstractItemView::SingleSelection);


    ui->playerProgressBar->setRange(0,100);
    ui->playerProgressBar->setValue(0);
    ui->playerHorizontalSlider->setRange(0,100);

    ui->playerHorizontalSlider->setEnabled(false);
    ui->playerProgressBar->setEnabled(false);
    ui->connectTCPPushButton->setEnabled(false);
    ui->playPushButton->setEnabled(false);
    ui->pausePushButton->setEnabled(false);

    connect(pcapfileparser, &PcapFileParser::udportcpExists,
            this, [=](bool udpExists, bool tcpExists)
            {

                ui->udporTcpComboBox->clear();
                ui->filteringComboBox->setCurrentIndex(-1);

                mapUdpIptoIP.clear();
                mapUdpPorttoPort.clear();
                mapUdpIpcomboSrcPort.clear();
                mapUdpIpSrcPortComboDstCombo.clear();

                mapTcpIptoIP.clear();
                mapTcpPorttoPort.clear();
                mapTcpIpcomboSrcPort.clear();
                mapTcpIpSrcPortComboDstCombo.clear();

                // You can now use the booleans freely inside this block
                if (udpExists)
                {
                    ui->udporTcpComboBox->addItem("UDP");

                    ui->filteringComboBox->setEnabled(true);
                    ui->udporTcpComboBox->setEnabled(true);
                }
                if (tcpExists)
                {
                    ui->udporTcpComboBox->addItem("TCP");

                    ui->filteringComboBox->setEnabled(true);
                    ui->udporTcpComboBox->setEnabled(true);
                }
                if(!udpExists && !tcpExists)
                {
                    QMessageBox::information(this, "Warning", "Udp or Tcp packets does not exist.");
                }
            });

    connect(pcapfileparser, &PcapFileParser::tcpList,
            this, [=] (QMap<QString, QSet<QString>>  tempMapTcpIptoIP,QMap<QString, QSet<QString>>  tempMapTcpPorttoPort,QMap<QString, QSet<QString>>  tempMapTcpIpcomboSrcPort,QMap<QString, QSet<QString>>  tempMapTcpIpSrcPortComboDstCombo)
            {
                if(!tempMapTcpIptoIP.isEmpty())
                {
                    mapTcpIptoIP = tempMapTcpIptoIP;
                    for (auto [ipAddress, protocolSet] : mapTcpIptoIP.asKeyValueRange())
                    {
                        qDebug() << "IP Address:" << ipAddress;
                        TcpIpList.push_back(ipAddress);
                    }
                }
                if(!tempMapTcpPorttoPort.isEmpty())
                {
                    mapTcpPorttoPort = tempMapTcpPorttoPort;
                    for (auto [ipAddress, protocolSet] : mapTcpPorttoPort.asKeyValueRange())
                    {
                        qDebug() << "IP Address:" << ipAddress;
                        TcpPortList.push_back(ipAddress);
                    }
                }
                if(!tempMapTcpIpcomboSrcPort.isEmpty())
                {
                    mapTcpIpcomboSrcPort = tempMapTcpIpcomboSrcPort;
                }
                if(!tempMapTcpIpSrcPortComboDstCombo.isEmpty())
                {
                    mapTcpIpSrcPortComboDstCombo = tempMapTcpIpSrcPortComboDstCombo;
                }
            });

    connect(pcapfileparser, &PcapFileParser::udpList,
            this, [=] (QMap<QString, QSet<QString>>  tempMapUdpIptoIP,QMap<QString, QSet<QString>>  tempMapUdpPorttoPort,QMap<QString, QSet<QString>>  tempMapUdpIpcomboSrcPort,QMap<QString, QSet<QString>>  tempMapUdpIpSrcPortComboDstCombo)
            {

                if(!tempMapUdpIptoIP.isEmpty())
                {
                    mapUdpIptoIP = tempMapUdpIptoIP;
                    for (auto [ipAddress, protocolSet] : tempMapUdpIptoIP.asKeyValueRange())
                    {
                        qDebug() << "IP Address:" << ipAddress;
                        UdpIpList.push_back(ipAddress);
                    }
                }
                if(!tempMapUdpPorttoPort.isEmpty())
                {
                    mapUdpPorttoPort = tempMapUdpPorttoPort;
                    for (auto [ipAddress, protocolSet] : mapUdpPorttoPort.asKeyValueRange())
                    {
                        qDebug() << "IP Address:" << ipAddress;
                        udpPortList.push_back(ipAddress);
                    }
                }
                if(!tempMapUdpIpcomboSrcPort.isEmpty())
                {
                    mapUdpIpcomboSrcPort = tempMapUdpIpcomboSrcPort;
                }
                if(!tempMapUdpIpSrcPortComboDstCombo.isEmpty())
                {
                    mapUdpIpSrcPortComboDstCombo = tempMapUdpIpSrcPortComboDstCombo;
                }
            });
}

MainWindow::~MainWindow()
{
    delete ui;
}

void MainWindow::on_browsePushButton_clicked()
{
    QString fileName;
    if(pcapFilePath.isEmpty())
    {
        fileName = QFileDialog::getOpenFileName(
            this,
            tr("Open Packet Capture File"),
            "/home",
            tr("Packet Capture Files (*.pcap *.pcapng);;All Files (*)")
            );
    }
    else
    {
        fileName = QFileDialog::getOpenFileName(
            this,
            tr("Open Packet Capture File"),
            pcapFilePath,
            tr("Packet Capture Files (*.pcap *.pcapng);;All Files (*)")
            );

    }

    if(!fileName.isEmpty())
    {
        if(pcapFilePath.isEmpty())
        {
            pcapFilePath = fileName;
            ui->bowseLineEdit->clear();
            ui->bowseLineEdit->setText(fileName);
            pcapfileparser->processFilePath(pcapFilePath);
        }
        else if(pcapFilePath != fileName)
        {
            pcapFilePath = fileName;
            ui->bowseLineEdit->clear();
            ui->bowseLineEdit->setText(fileName);
            pcapfileparser->processFilePath(pcapFilePath);
        }
    }
}

void MainWindow::on_filteringComboBox_currentIndexChanged(int index)
{
    qDebug()<<index;
    if(index == -1)
    {
        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->setEnabled(false);
        ui->dstIpListWidget->setEnabled(false);

        ui->srcPortListWidget->setEnabled(false);
        ui->dstPortListWidget->setEnabled(false);
    }
    if(index == 0)
    {
        ui->srcPortListWidget->setEnabled(true);
        ui->dstPortListWidget->setEnabled(true);

        ui->srcIpListWidget->setEnabled(false);
        ui->dstIpListWidget->setEnabled(false);
        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        if(ui->udporTcpComboBox->currentIndex() == 0)
        {
            ui->srcPortListWidget->addItems(udpPortList);
        }
        else if(ui->udporTcpComboBox->currentIndex() == 1)
        {
            ui->srcPortListWidget->addItems(TcpPortList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();

    }
    else if(index == 1)
    {
        ui->srcIpListWidget->setEnabled(true);
        ui->dstIpListWidget->setEnabled(true);

        ui->srcPortListWidget->setEnabled(false);
        ui->dstPortListWidget->setEnabled(false);
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        if(UdpIpList.isEmpty())
        {
            qDebug()<<"udp empty";
        }
        if(TcpIpList.isEmpty())
        {
            qDebug()<<"tcp empty";
        }
        if(ui->udporTcpComboBox->currentIndex() == 0)
        {
            ui->srcIpListWidget->addItems(UdpIpList);
        }
        else if(ui->udporTcpComboBox->currentIndex() == 1)
        {
            ui->srcIpListWidget->addItems(TcpIpList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 2)
    {

        ui->srcIpListWidget->setEnabled(true);
        ui->dstIpListWidget->setEnabled(true);

        ui->srcPortListWidget->setEnabled(true);
        ui->dstPortListWidget->setEnabled(true);

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        if(ui->udporTcpComboBox->currentIndex() == 0)
        {
            ui->srcIpListWidget->addItems(UdpIpList);
        }
        else if(ui->udporTcpComboBox->currentIndex() == 1)
        {
            ui->srcIpListWidget->addItems(TcpIpList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
}

void MainWindow::on_udporTcpComboBox_currentIndexChanged(int index)
{
    if(ui->udporTcpComboBox->currentText() == "UDP")
    {
        if(ui->filteringComboBox->currentIndex() == 0)
        {
            on_filteringComboBox_currentIndexChanged(0);
        }
        else if(ui->filteringComboBox->currentIndex() == 1)
        {
            on_filteringComboBox_currentIndexChanged(1);
        }
        else if(ui->filteringComboBox->currentIndex() == 2)
        {
            on_filteringComboBox_currentIndexChanged(2);
        }
    }
    else if(ui->udporTcpComboBox->currentText() == "TCP")
    {
        if(ui->filteringComboBox->currentIndex() == 0)
        {
            on_filteringComboBox_currentIndexChanged(0);
        }
        else if(ui->filteringComboBox->currentIndex() == 1)
        {
            on_filteringComboBox_currentIndexChanged(1);
        }
        else if(ui->filteringComboBox->currentIndex() == 2)
        {
            on_filteringComboBox_currentIndexChanged(2);
        }
    }
}

void MainWindow::on_srcIpListWidget_itemClicked(QListWidgetItem *item)
{
    if(selectedsrcIP != item->text())
    {
        selectedsrcIP.clear();
        selecteddstIp.clear();
        selectedsrcPort.clear();
        selecteddstPort.clear();

        dstIpList.clear();
        ui->dstIpListWidget->clear();
        srcPortList.clear();
        ui->srcPortListWidget->clear();
        dstPortList.clear();
        ui->dstPortListWidget->clear();

        selectedsrcIP = item->text();

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            for (const QString &port : mapUdpIptoIP[item->text()])
            {
                dstIpList.push_back(port);
            }
            ui->dstIpListWidget->addItems(dstIpList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {

            for (const QString &port : mapTcpIptoIP[item->text()])
            {
                dstIpList.push_back(port);
            }
            ui->dstIpListWidget->addItems(dstIpList);
        }
    }
    else
    {
        item->setSelected(false);

        selecteddstIp.clear();
        selectedsrcPort.clear();
        selecteddstPort.clear();
        selectedsrcIP.clear();

        srcPortList.clear();
        ui->srcPortListWidget->clear();
        dstIpList.clear();
        ui->dstIpListWidget->clear();
        dstPortList.clear();
        ui->dstPortListWidget->clear();
    }
}


void MainWindow::on_dstIpListWidget_itemClicked(QListWidgetItem *item)
{
    if(selectedsrcIP != item->text())
    {
        selecteddstIp.clear();
        selectedsrcPort.clear();
        selecteddstPort.clear();

        srcPortList.clear();
        ui->srcPortListWidget->clear();
        dstPortList.clear();
        ui->dstPortListWidget->clear();
        selecteddstIp = item->text();



        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            if(ui->filteringComboBox->currentIndex() == 2)
            {
                for (const QString &port : mapUdpIpcomboSrcPort[selectedsrcIP+"\t"+item->text()])
                {
                    srcPortList.push_back(port);
                }
                ui->srcPortListWidget->addItems(srcPortList);
            }
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            if(ui->filteringComboBox->currentIndex() == 2)
            {
                qDebug()<<"hello";
                for (const QString &port : mapTcpIpcomboSrcPort[selectedsrcIP+"\t"+item->text()])
                {
                    srcPortList.push_back(port);
                }
                qDebug()<<"size"<<srcPortList.size();
                if(srcPortList.isEmpty())
                {
                    qDebug()<<"empty";
                }
                ui->srcPortListWidget->addItems(srcPortList);
            }
        }
    }
    else
    {
        item->setSelected(false);

        selecteddstIp.clear();
        selectedsrcPort.clear();
        selecteddstPort.clear();

        srcPortList.clear();
        ui->srcPortListWidget->clear();
        dstPortList.clear();
        ui->dstPortListWidget->clear();
    }
}


void MainWindow::on_srcPortListWidget_itemClicked(QListWidgetItem *item)
{
    if(selectedsrcPort != item->text())
    {
        selectedsrcPort.clear();
        selectedsrcPort = item->text();
        selecteddstPort.clear();

        dstPortList.clear();
        ui->dstPortListWidget->clear();

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            if(ui->filteringComboBox->currentIndex() == 0)
            {
                for (const QString &port : mapUdpPorttoPort[item->text()])
                {
                    dstPortList.push_back(port);
                }
                ui->dstPortListWidget->addItems(dstPortList);
            }
            else if(ui->filteringComboBox->currentIndex() == 2)
            {
                for (const QString &port : mapUdpIpSrcPortComboDstCombo[selectedsrcIP+"\t"+selecteddstIp+"\t"+item->text()])
                {
                    dstPortList.push_back(port);
                }
                ui->dstPortListWidget->addItems(dstPortList);
            }
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            if(ui->filteringComboBox->currentIndex() == 0)
            {
                for (const QString &port : mapTcpPorttoPort[item->text()])
                {
                    dstPortList.push_back(port);
                }
                ui->dstPortListWidget->addItems(dstPortList);
            }
            else if(ui->filteringComboBox->currentIndex() == 2)
            {

                for (const QString &port : mapTcpIpSrcPortComboDstCombo[selectedsrcIP+"\t"+selecteddstIp+"\t"+item->text()])
                {
                    dstPortList.push_back(port);
                }
                ui->dstPortListWidget->addItems(dstPortList);
            }
        }
    }
    else
    {
        selectedsrcPort.clear();
        selecteddstPort.clear();
        ui->dstPortListWidget->clear();
        item->setSelected(false);
    }
}


void MainWindow::on_dstPortListWidget_itemClicked(QListWidgetItem *item)
{
    if(selecteddstPort != item->text())
    {
        selecteddstPort.clear();
        selecteddstPort = item->text();
    }
    else
    {
        selecteddstPort.clear();
        item->setSelected(false);
    }
}



void MainWindow::on_DstIPLineEdit_editingFinished()
{
    qDebug()<<"hello";
    QHostAddress address;
    QString ipText = ui->DstIPLineEdit->text().trimmed();

    // 1. Verify Qt can parse it, it is IPv4, and contains exactly 3 dots
    if (address.setAddress(ipText) &&
        address.protocol() == QAbstractSocket::IPv4Protocol &&
        ipText.count('.') == 3)
    {
        dstIpAddress = address;
        // Valid 4-octet IPv4 address (e.g., 192.168.0.1)
    }
    else
    {
        QMessageBox::information(this, "Warning", "IP Address is invalid.");
        dstIpAddress.clear();
        ui->DstIPLineEdit->clear();
    }
}


void MainWindow::on_playUDPorTCPComboBox_currentIndexChanged(int index)
{
    if(index == 1)
    {
        if( !(ui->DstIPLineEdit->text().isEmpty()) && !(ui->dstPortlineEdit->text().isEmpty()))
        {
            ui->connectTCPPushButton->setEnabled(true);

        }
        else
        {
            QMessageBox::information(this, "Warning", "Set Destination IP address and ports.");
            ui->connectTCPPushButton->setEnabled(false);
            ui->playUDPorTCPComboBox->setCurrentIndex(-1);
        }
        // ui->connectTCPPushButton->setEnabled(false);
    }
    else if(index == 0)
    {
        if(!(ui->dstPortlineEdit->text().isEmpty()))
        {
            ui->connectTCPPushButton->setEnabled(true);
        }
        else
        {
            QMessageBox::information(this, "Warning", "SetDestination port.");
            ui->connectTCPPushButton->setEnabled(false);
            ui->playUDPorTCPComboBox->setCurrentIndex(-1);
        }
    }

}

void MainWindow::on_connectTCPPushButton_clicked()
{
    ui->connectTCPPushButton->setEnabled(false);
    if(ui->playUDPorTCPComboBox->currentIndex() == 1)
    {
        if(ui->userIPComboBox->currentIndex()>=0)
        {
            srcIpAddress.clear();
            srcIpAddress.setAddress(ui->userIPComboBox->currentText());
        }
        else
        {
            srcIpAddress.clear();
        }

        if(!ui->DstIPLineEdit->text().isEmpty())
        {
            dstIpAddress.clear();
            dstIpAddress.setAddress(ui->DstIPLineEdit->text());
        }
        else
        {
            dstIpAddress.clear();
        }

        if(!ui->srcPortLineEdit->text().isEmpty())
        {
            srcPort.clear();
            srcPort = ui->srcPortLineEdit->text();
        }
        else
        {
            srcPort.clear();
        }

        if(!ui->dstPortlineEdit->text().isEmpty())
        {
            dstPort.clear();
            dstPort = ui->dstPortlineEdit->text();
        }
        else
        {
            dstPort.clear();
        }

        bool connected = packetplayer->connectTcp(srcIpAddress,dstIpAddress,srcPort,dstPort);
    }
    else if(ui->playUDPorTCPComboBox->currentIndex() == 0)
    {

        if(ui->userIPComboBox->currentIndex()>=0)
        {
            srcIpAddress.clear();
            srcIpAddress.setAddress(ui->userIPComboBox->currentText());
        }
        else
        {
            srcIpAddress.clear();
        }

        if(!ui->DstIPLineEdit->text().isEmpty())
        {
            dstIpAddress.clear();
            dstIpAddress.setAddress(ui->DstIPLineEdit->text());
        }
        else
        {
            dstIpAddress.clear();
        }

        if(!ui->srcPortLineEdit->text().isEmpty())
        {
            srcPort.clear();
            srcPort = ui->srcPortLineEdit->text();
        }
        else
        {
            srcPort.clear();
        }

        if(!ui->dstPortlineEdit->text().isEmpty())
        {
            dstPort.clear();
            dstPort = ui->dstPortlineEdit->text();
        }
        else
        {
            dstPort.clear();
        }
        bool connected = packetplayer->connectUdp(srcIpAddress,dstIpAddress,srcPort,dstPort);
        qDebug()<<"in udp";
        if(connected == true)
        {
            qDebug()<<"udp connected";
            bool packetfileempty = packetplayer->filterPcapFile(ui->udporTcpComboBox->currentIndex(),pcapFilePath,selectedsrcIP,selecteddstIp,selectedsrcPort,selecteddstPort);
            if(packetfileempty == true)
            {
                ui->playerHorizontalSlider->setEnabled(true);
                ui->playerProgressBar->setEnabled(true);
                ui->playPushButton->setEnabled(true);
                ui->pausePushButton->setEnabled(true);
                ui->timerSpeedSpinBox->setEnabled(true);
            }
            else
            {
                qDebug()<<"file is empty";
                ui->playerHorizontalSlider->setEnabled(false);
                ui->playerProgressBar->setEnabled(false);
                ui->playPushButton->setEnabled(false);
                ui->pausePushButton->setEnabled(false);
                ui->timerSpeedSpinBox->setEnabled(false);
            }
        }

    }
    ui->connectTCPPushButton->setEnabled(true);
}

void MainWindow::tcpConnectionStatus(bool tcpStatus)
{
    if(tcpStatus == true && ui->udporTcpComboBox->currentIndex() == 1)
    {
        bool packetfileempty = packetplayer->filterPcapFile(ui->udporTcpComboBox->currentIndex(),pcapFilePath,selectedsrcIP,selecteddstIp,selectedsrcPort,selecteddstPort);
        if(packetfileempty == true)
        {
            ui->playerHorizontalSlider->setEnabled(true);
            ui->playerProgressBar->setEnabled(true);
            ui->playPushButton->setEnabled(true);
            ui->pausePushButton->setEnabled(true);
            ui->timerSpeedSpinBox->setEnabled(true);
        }
        else
        {
            ui->playerHorizontalSlider->setEnabled(false);
            ui->playerProgressBar->setEnabled(false);
            ui->playPushButton->setEnabled(false);
            ui->pausePushButton->setEnabled(false);
            ui->timerSpeedSpinBox->setEnabled(false);
        }
    }
    else if(tcpStatus == false && ui->udporTcpComboBox->currentIndex() == 1)
    {
        ui->playerHorizontalSlider->setEnabled(false);
        ui->playerProgressBar->setEnabled(false);
        ui->playPushButton->setEnabled(false);
        ui->pausePushButton->setEnabled(false);
        ui->timerSpeedSpinBox->setEnabled(false);
    }
}


void MainWindow::on_playPushButton_clicked(bool checked)
{
    if(checked)
    {
        ui->playPushButton->setText("Stop");
        ui->playPushButton->setChecked(true);
        ui->pausePushButton->setText("Pause");
        ui->pausePushButton->setChecked(false);
        qDebug()<<"start";
        packetplayer->startorstopthePackets(checked);
    }
    else
    {
        qDebug()<<"stop";
        ui->playPushButton->setText("Play");
        ui->playPushButton->setChecked(false);
        ui->pausePushButton->setText("Pause");
        ui->pausePushButton->setChecked(false);
        packetplayer->startorstopthePackets(checked);
    }
}


void MainWindow::on_pausePushButton_clicked(bool checked)
{
    if(ui->playPushButton->text() == "Stop")
    {
        if(checked)
        {
            ui->pausePushButton->setText("Resume");
            ui->pausePushButton->setChecked(true);
            packetplayer->pausethePackets(checked);
        }
        else
        {
            ui->pausePushButton->setText("Pause");
            ui->pausePushButton->setChecked(false);
            packetplayer->pausethePackets(checked);
        }
    }
}


void MainWindow::on_timerSpeedSpinBox_valueChanged(int arg1)
{
    qDebug()<<ui->timerSpeedSpinBox->value();
    packetplayer->timerspeed(arg1);
}


void MainWindow::on_timerSpeedSpinBox_textChanged(const QString &arg1)
{
    qDebug()<<ui->timerSpeedSpinBox->value();
    packetplayer->timerspeed(arg1.toInt());
}


void MainWindow::on_playerHorizontalSlider_sliderMoved(int position)
{
    qDebug()<<"position";
    packetplayer->setCurrIndexwithSlider(position);
}


void MainWindow::on_playerHorizontalSlider_sliderPressed()
{
    qDebug()<<"position";
    packetplayer->setCurrIndexwithSlider(ui->playerHorizontalSlider->value());
}

