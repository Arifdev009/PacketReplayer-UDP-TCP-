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
    ui->playUDPorTCPComboBox->addItem("TCP CLIENT");
    ui->playUDPorTCPComboBox->addItem("TCP SERVER");

    packetplayer = new packetPlayer;
    packetplayerThread = new QThread(this);
    packetplayer->moveToThread(packetplayerThread);
    packetplayer->initializeClassMembers();
    packetplayerThread->start();

    connect(packetplayer,&packetPlayer::tcpConnectionStatus,this,&MainWindow::tcpConnectionStatus);
    connect(packetplayer,&packetPlayer::tcpServerConnectionStatus,this,&MainWindow::tcpServerConnectionStatus);
    connect(packetplayer,&packetPlayer::packetsEnded,this,&MainWindow::on_playPushButton_clicked);
    connect(packetplayer,&packetPlayer::packetPercentageSent,this,
            [=](int percent)
            {
                ui->playerProgressBar->setValue(percent);
            });


    connect(this,&MainWindow::setTimerSpeed,packetplayer,&packetPlayer::timerspeed);
    connect(this,&MainWindow::setPausethePackets,packetplayer,&packetPlayer::pausethePackets);
    connect(this,&MainWindow::setStartorstopthePackets,packetplayer,&packetPlayer::startorstopthePackets);
    connect(this,&MainWindow::setUICurrIndexwithSlider,packetplayer,&packetPlayer::setCurrIndexwithSlider);

    connect(this,&MainWindow::setCreateUDP,packetplayer,&packetPlayer::connectUdp);
    connect(this,&MainWindow::setCreateTcp,packetplayer,&packetPlayer::connectTcp);
    connect(this,&MainWindow::setCreateTcpServer,packetplayer,&packetPlayer::startTcpServer);

    connect(this,&MainWindow::createparseFilterPcapFile,packetplayer,&packetPlayer::filterPcapFile);

    connect(packetplayer,&packetPlayer::creatingUdpStatus,this,&MainWindow::creatingUdpStatus);
    connect(packetplayer,&packetPlayer::creatingTcpStatus,this,&MainWindow::creatingTcpStatus);
    connect(packetplayer,&packetPlayer::creatingTcpServerStatus,this,&MainWindow::creatingTcpServerStatus);

    connect(packetplayer,&packetPlayer::parseFilterPcapFileStatus,this,&MainWindow::parseFilterPcapFileStatus);



    pcapFileParserThread = new QThread();
    pcapfileparser = new PcapFileParser;

    pcapfileparser->moveToThread(pcapFileParserThread);
    pcapFileParserThread->start();

    // In your UI Controller / MainWindow
    connect(this, &MainWindow::startParsing, pcapfileparser, &PcapFileParser::processFilePath);
    // This safely pushes the execution to the background thread

    // qDebug()<<"main thread"<<
    ui->udporTcpComboBox->setPlaceholderText("select UDP or TCP");


    ui->filteringComboBox->setPlaceholderText("select Filter");
    ui->filteringComboBox->addItem("Src Port");
    ui->filteringComboBox->addItem("Dst Port");
    ui->filteringComboBox->addItem("Src Ip");
    ui->filteringComboBox->addItem("Dst Ip");
    ui->filteringComboBox->addItem("Port");
    ui->filteringComboBox->addItem("IP Address");
    ui->filteringComboBox->addItem("Port and Ip");

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
    ui->connectUDPTCPPushButton->setEnabled(false);
    ui->playPushButton->setEnabled(false);
    ui->pausePushButton->setEnabled(false);

    connect(pcapfileparser, &PcapFileParser::udportcpExists,
            this, [=](bool udpExists, bool tcpExists)
            {

                QString currText = ui->udporTcpComboBox->currentText();

                ui->udporTcpComboBox->clear();





                mapUdpIptoIP.clear();
                mapUdpPorttoPort.clear();
                mapUdpIpcomboSrcPort.clear();
                mapUdpIpSrcPortComboDstCombo.clear();

                mapTcpIptoIP.clear();
                mapTcpPorttoPort.clear();
                mapTcpIpcomboSrcPort.clear();
                mapTcpIpSrcPortComboDstCombo.clear();


                // bool protocolPacketsExist = false;

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

                if(currText == "TCP" || currText == "UDP")
                {
                    ui->udporTcpComboBox->setCurrentText(currText);
                }

                if(!udpExists && !tcpExists)
                {
                    QMessageBox::information(this, "Warning", "Udp or Tcp packets does not exist.");
                }
            });

    connect(pcapfileparser, &PcapFileParser::tcpList,
            this, [=] (QSet<QString> tempqsetTcpSrcIp,QSet<QString> tempqsetTcpDstIp,QSet<QString> tempqsetTcpSrcPort,QSet<QString> tempqsetTcpDstPort,QMap<QString, QSet<QString>>  tempMapTcpIptoIP,QMap<QString, QSet<QString>>  tempMapTcpPorttoPort,QMap<QString, QSet<QString>>  tempMapTcpIpcomboSrcPort,QMap<QString, QSet<QString>>  tempMapTcpIpSrcPortComboDstCombo)
            {

                tcpSrcPortList.clear();
                tcpSrcIpList.clear();



                tcpDstPortList.clear();
                tcpDstIplist.clear();
                if(!tempMapTcpIptoIP.isEmpty())
                {
                    mapTcpIptoIP = tempMapTcpIptoIP;
                    // for (auto [ipAddress, protocolSet] : mapTcpIptoIP.asKeyValueRange())
                    // {
                    //     qDebug() << "IP Address:" << ipAddress;
                    //     tcpSrcIpList.push_back(ipAddress);
                    // }
                }
                if(!tempMapTcpPorttoPort.isEmpty())
                {
                    mapTcpPorttoPort = tempMapTcpPorttoPort;
                    // for (auto [ipAddress, protocolSet] : mapTcpPorttoPort.asKeyValueRange())
                    // {
                    //     qDebug() << "IP Address:" << ipAddress;
                    //     tcpSrcPortList.push_back(ipAddress);
                    // }
                }
                if(!tempMapTcpIpcomboSrcPort.isEmpty())
                {
                    mapTcpIpcomboSrcPort = tempMapTcpIpcomboSrcPort;
                }
                if(!tempMapTcpIpSrcPortComboDstCombo.isEmpty())
                {
                    mapTcpIpSrcPortComboDstCombo = tempMapTcpIpSrcPortComboDstCombo;
                }
                if(!tempqsetTcpSrcIp.isEmpty())
                {
                    // qsetTcpSrcIp = tempqsetTcpSrcIp;
                    for(const QString  &tempIp: std::as_const(tempqsetTcpSrcIp))
                    {
                        tcpSrcIpList.append(tempIp);
                    }
                    std::sort(tcpSrcIpList.begin(),tcpSrcIpList.end());
                    // tcpSrcIpList = tempqsetTcpSrcIp;
                }
                if(!tempqsetTcpDstIp.isEmpty())
                {
                    // qsetTcpDstIp = tempqsetTcpDstIp;
                    for(const QString  &tempIp: std::as_const(tempqsetTcpDstIp))
                    {
                        tcpDstIplist.append(tempIp);
                    }
                    std::sort(tcpDstIplist.begin(),tcpDstIplist.end());
                }
                if(!tempqsetTcpSrcPort.isEmpty())
                {
                    // qsetTcpSrcPort = tempqsetTcpSrcPort;
                    for(const QString  &tempIp: std::as_const(tempqsetTcpSrcPort))
                    {
                        tcpSrcPortList.append(tempIp);
                    }
                    std::sort(tcpSrcPortList.begin(),tcpSrcPortList.end());
                }
                if(!tempqsetTcpDstPort.isEmpty())
                {
                    // qsetTcpDstPort = tempqsetTcpDstPort;
                    for(const QString  &tempIp: std::as_const(tempqsetTcpDstPort))
                    {
                        tcpDstPortList.append(tempIp);
                    }
                    std::sort(tcpDstPortList.begin(),tcpDstPortList.end());
                }


                if(ui->udporTcpComboBox->currentIndex() != -1)
                {
                    int currIndex = ui->filteringComboBox->currentIndex();

                    ui->filteringComboBox->setCurrentIndex(currIndex);
                    on_filteringComboBox_currentIndexChanged(currIndex);
                }
                else
                {
                    ui->filteringComboBox->setCurrentIndex(-1);
                }

            });

    connect(pcapfileparser, &PcapFileParser::udpList,
            this, [=] (QSet<QString> tempqsetUdpSrcIp,QSet<QString> tempqsetUdpDstIp,QSet<QString> tempqsetUdpSrcPort,QSet<QString> tempqsetUdpDstPort,QMap<QString, QSet<QString>>  tempMapUdpIptoIP,QMap<QString, QSet<QString>>  tempMapUdpPorttoPort,QMap<QString, QSet<QString>>  tempMapUdpIpcomboSrcPort,QMap<QString, QSet<QString>>  tempMapUdpIpSrcPortComboDstCombo)
            {
                udpSrcPortList.clear();
                udpSrcIpList.clear();
                udpDstPortList.clear();
                udpDstIpList.clear();
                if(!tempMapUdpIptoIP.isEmpty())
                {
                    mapUdpIptoIP = tempMapUdpIptoIP;
                    // for (auto [ipAddress, protocolSet] : tempMapUdpIptoIP.asKeyValueRange())
                    // {
                    //     qDebug() << "IP Address:" << ipAddress;
                    //     udpSrcIpList.push_back(ipAddress);
                    // }
                }
                if(!tempMapUdpPorttoPort.isEmpty())
                {
                    mapUdpPorttoPort = tempMapUdpPorttoPort;
                    // for (auto [ipAddress, protocolSet] : mapUdpPorttoPort.asKeyValueRange())
                    // {
                    //     qDebug() << "IP Address:" << ipAddress;
                    //     udpSrcPortList.push_back(ipAddress);
                    // }
                }
                if(!tempMapUdpIpcomboSrcPort.isEmpty())
                {
                    mapUdpIpcomboSrcPort = tempMapUdpIpcomboSrcPort;
                }
                if(!tempMapUdpIpSrcPortComboDstCombo.isEmpty())
                {
                    mapUdpIpSrcPortComboDstCombo = tempMapUdpIpSrcPortComboDstCombo;
                }
                if(!tempqsetUdpSrcIp.isEmpty())
                {
                    // qsetUdpSrcIp = tempqsetUdpSrcIp;
                    for(const QString  &tempIp: std::as_const(tempqsetUdpSrcIp))
                    {
                        udpSrcIpList.append(tempIp);
                    }
                    std::sort(udpSrcIpList.begin(),udpSrcIpList.end());

                }
                if(!tempqsetUdpDstIp.isEmpty())
                {
                    // qsetUdpDstIp = tempqsetUdpDstIp;
                    for(const QString  &tempIp: std::as_const(tempqsetUdpDstIp))
                    {
                        udpDstIpList.append(tempIp);
                    }
                    std::sort(udpDstIpList.begin(),udpDstIpList.end());

                }
                if(!tempqsetUdpSrcPort.isEmpty())
                {
                    // qsetUdpSrcPort = tempqsetUdpSrcPort;
                    for(const QString  &tempIp: std::as_const(tempqsetUdpSrcPort))
                    {
                        udpSrcPortList.append(tempIp);
                    }
                    std::sort(udpSrcPortList.begin(),udpSrcPortList.end());
                }
                if(!tempqsetUdpDstPort.isEmpty())
                {
                    // qsetUdpDstPort = tempqsetUdpDstPort;
                    for(const QString  &tempIp: std::as_const(tempqsetUdpDstPort))
                    {
                        udpDstPortList.append(tempIp);
                    }
                    std::sort(udpDstPortList.begin(),udpDstPortList.end());
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
        pcapFilePath = fileName;
        ui->bowseLineEdit->clear();
        ui->bowseLineEdit->setText(fileName);
        on_playPushButton_clicked(false);
        emit startParsing(pcapFilePath);
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
        ui->srcIpListWidget->setEnabled(false);
        ui->dstIpListWidget->setEnabled(false);
        ui->srcPortListWidget->setEnabled(true);
        ui->dstPortListWidget->setEnabled(false);
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcPortListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->srcPortListWidget->addItems(udpSrcPortList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->srcPortListWidget->addItems(tcpSrcPortList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 1)
    {
        ui->srcIpListWidget->setEnabled(false);
        ui->dstIpListWidget->setEnabled(false);
        ui->srcPortListWidget->setEnabled(false);
        ui->dstPortListWidget->setEnabled(true);
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->dstPortListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->dstPortListWidget->addItems(udpDstPortList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->dstPortListWidget->addItems(tcpDstPortList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 2)
    {
        ui->srcIpListWidget->setEnabled(true);
        ui->dstIpListWidget->setEnabled(false);
        ui->srcPortListWidget->setEnabled(false);
        ui->dstPortListWidget->setEnabled(false);
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->srcIpListWidget->addItems(udpSrcIpList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->srcIpListWidget->addItems(tcpSrcIpList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 3)
    {
        ui->srcIpListWidget->setEnabled(false);
        ui->dstIpListWidget->setEnabled(true);
        ui->srcPortListWidget->setEnabled(false);
        ui->dstPortListWidget->setEnabled(false);
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->dstIpListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->dstIpListWidget->addItems(udpDstIpList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->dstIpListWidget->addItems(udpSrcIpList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 4)
    {
        ui->srcPortListWidget->setEnabled(true);
        ui->dstPortListWidget->setEnabled(true);

        ui->srcIpListWidget->setEnabled(false);
        ui->dstIpListWidget->setEnabled(false);


        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcPortListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->dstPortListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->srcPortListWidget->addItems(udpSrcPortList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->srcPortListWidget->addItems(tcpSrcPortList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 5)
    {
        ui->srcIpListWidget->setEnabled(true);
        ui->dstIpListWidget->setEnabled(true);

        ui->srcPortListWidget->setEnabled(false);
        ui->dstPortListWidget->setEnabled(false);

        ui->srcIpListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->dstIpListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        if(udpSrcIpList.isEmpty())
        {
            qDebug()<<"udp empty";
        }
        if(tcpSrcIpList.isEmpty())
        {
            qDebug()<<"tcp empty";
        }
        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->srcIpListWidget->addItems(udpSrcIpList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->srcIpListWidget->addItems(tcpSrcIpList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
    else if(index == 6)
    {

        ui->srcIpListWidget->setEnabled(true);
        ui->dstIpListWidget->setEnabled(true);

        ui->srcPortListWidget->setEnabled(true);
        ui->dstPortListWidget->setEnabled(true);

        ui->srcIpListWidget->clear();
        ui->dstIpListWidget->clear();
        ui->srcPortListWidget->clear();
        ui->dstPortListWidget->clear();

        ui->srcIpListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->dstIpListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->srcPortListWidget->setSelectionMode(QAbstractItemView::SingleSelection);
        ui->dstPortListWidget->setSelectionMode(QAbstractItemView::MultiSelection);

        if(ui->udporTcpComboBox->currentText() == "UDP")
        {
            ui->srcIpListWidget->addItems(udpSrcIpList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            ui->srcIpListWidget->addItems(tcpSrcIpList);
        }

        selectedsrcIP.clear();
        selectedsrcPort.clear();
        selecteddstIp.clear();
        selecteddstPort.clear();
    }
}

void MainWindow::on_udporTcpComboBox_currentIndexChanged(int index)
{
    Q_UNUSED(index);
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
        else if(ui->filteringComboBox->currentIndex() == 3)
        {
            on_filteringComboBox_currentIndexChanged(3);
        }
        else if(ui->filteringComboBox->currentIndex() == 4)
        {
            on_filteringComboBox_currentIndexChanged(4);
        }
        else if(ui->filteringComboBox->currentIndex() == 5)
        {
            on_filteringComboBox_currentIndexChanged(5);
        }
        else if(ui->filteringComboBox->currentIndex() == 6)
        {
            on_filteringComboBox_currentIndexChanged(6);
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
        else if(ui->filteringComboBox->currentIndex() == 3)
        {
            on_filteringComboBox_currentIndexChanged(3);
        }
        else if(ui->filteringComboBox->currentIndex() == 4)
        {
            on_filteringComboBox_currentIndexChanged(4);
        }
        else if(ui->filteringComboBox->currentIndex() == 5)
        {
            on_filteringComboBox_currentIndexChanged(5);
        }
        else if(ui->filteringComboBox->currentIndex() == 6)
        {
            on_filteringComboBox_currentIndexChanged(6);
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
            std::sort(dstIpList.begin(),dstIpList.end());
            ui->dstIpListWidget->addItems(dstIpList);
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {

            for (const QString &port : mapTcpIptoIP[item->text()])
            {
                dstIpList.push_back(port);
            }
            std::sort(dstIpList.begin(),dstIpList.end());
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
            if(ui->filteringComboBox->currentIndex() == 6)
            {
                if(mapUdpIpcomboSrcPort[selectedsrcIP+"\t"+item->text()].isEmpty())
                {
                    qDebug()<<"map is empty";
                }
                for (const QString &port : std::as_const(mapUdpIpcomboSrcPort[selectedsrcIP+"\t"+item->text()]))
                {
                    srcPortList.push_back(port);
                }
                std::sort(srcPortList.begin(),srcPortList.end());
                ui->srcPortListWidget->addItems(srcPortList);
            }
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            if(ui->filteringComboBox->currentIndex() == 6)
            {
                qDebug()<<"hello";
                if(mapTcpIpcomboSrcPort[selectedsrcIP+"\t"+item->text()].isEmpty())
                {
                    qDebug()<<"map is empty";
                }
                for (const QString &port : mapTcpIpcomboSrcPort[selectedsrcIP+"\t"+item->text()])
                {
                    srcPortList.push_back(port);
                }
                qDebug()<<"size"<<srcPortList.size();
                if(srcPortList.isEmpty())
                {
                    qDebug()<<"empty";
                }
                std::sort(srcPortList.begin(),srcPortList.end());
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
            if(ui->filteringComboBox->currentIndex() == 4)
            {
                for (const QString &port : mapUdpPorttoPort[item->text()])
                {
                    dstPortList.push_back(port);
                }
                std::sort(dstPortList.begin(),dstPortList.end());
                ui->dstPortListWidget->addItems(dstPortList);
            }
            else if(ui->filteringComboBox->currentIndex() == 6)
            {
                for (const QString &port : mapUdpIpSrcPortComboDstCombo[selectedsrcIP+"\t"+selecteddstIp+"\t"+item->text()])
                {
                    dstPortList.push_back(port);
                }
                std::sort(dstPortList.begin(),dstPortList.end());
                ui->dstPortListWidget->addItems(dstPortList);
            }
        }
        else if(ui->udporTcpComboBox->currentText() == "TCP")
        {
            if(ui->filteringComboBox->currentIndex() == 4)
            {
                for (const QString &port : mapTcpPorttoPort[item->text()])
                {
                    dstPortList.push_back(port);
                }
                std::sort(dstPortList.begin(),dstPortList.end());
                ui->dstPortListWidget->addItems(dstPortList);
            }
            else if(ui->filteringComboBox->currentIndex() == 6)
            {

                for (const QString &port : mapTcpIpSrcPortComboDstCombo[selectedsrcIP+"\t"+selecteddstIp+"\t"+item->text()])
                {
                    dstPortList.push_back(port);
                }
                std::sort(dstPortList.begin(),dstPortList.end());
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
            ui->connectUDPTCPPushButton->setEnabled(true);

        }
        else
        {
            QMessageBox::information(this, "Warning", "Set Destination IP address and ports.");
            ui->connectUDPTCPPushButton->setEnabled(false);
            ui->playUDPorTCPComboBox->setCurrentIndex(-1);
        }
        // ui->connectUDPTCPPushButton->setEnabled(false);
    }
    else if(index == 0)
    {
        if(!(ui->dstPortlineEdit->text().isEmpty()))
        {
            ui->connectUDPTCPPushButton->setEnabled(true);
        }
        else
        {
            QMessageBox::information(this, "Warning", "SetDestination port.");
            ui->connectUDPTCPPushButton->setEnabled(false);
            ui->playUDPorTCPComboBox->setCurrentIndex(-1);
        }
    }
    else if(index == 2)
    {
        if(!(ui->srcPortLineEdit->text().isEmpty()))
        {
            ui->connectUDPTCPPushButton->setEnabled(true);
        }
        else
        {
            QMessageBox::information(this, "Warning", "Set src port.");
            ui->connectUDPTCPPushButton->setEnabled(false);
            ui->playUDPorTCPComboBox->setCurrentIndex(-1);
        }
    }

}

void MainWindow::on_connectUDPTCPPushButton_clicked()
{
    ui->connectUDPTCPPushButton->setEnabled(false);
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

        emit setCreateTcp(srcIpAddress,dstIpAddress,srcPort,dstPort);
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
        emit setCreateUDP(srcIpAddress,dstIpAddress,srcPort,dstPort);
        qDebug()<<"in udp";

    }
    else if(ui->playUDPorTCPComboBox->currentIndex() == 2)
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

        emit setCreateTcpServer(srcIpAddress,dstIpAddress,srcPort,dstPort);
    }
    ui->connectUDPTCPPushButton->setEnabled(true);
}

void MainWindow::creatingUdpStatus(bool status)
{
    if(status == true)
    {
        if(ui->udporTcpComboBox->currentIndex() == -1)
        {
            QMessageBox::information(this, "Success", "Please select UDP or TCP.");
        }
        else
        {
            QSet<QString> selectedSrcIpSet;
            QSet<QString> selectedDstIpSet;
            QSet<QString> selectedSrcPortSet;
            QSet<QString> selectedDstPortSet;
            if(ui->filteringComboBox->currentIndex() == 2 || ui->filteringComboBox->currentIndex() == 5 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempSrcIP = ui->srcIpListWidget->selectedItems();
                for(const QListWidgetItem *srcIp : std::as_const(tempSrcIP))
                {
                    selectedSrcIpSet.insert(srcIp->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 3 || ui->filteringComboBox->currentIndex() == 5 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempDstIP = ui->dstIpListWidget->selectedItems();
                for(const QListWidgetItem *dstIp : std::as_const(tempDstIP))
                {
                    selectedDstIpSet.insert(dstIp->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 0 || ui->filteringComboBox->currentIndex() == 4 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempSrcPort = ui->srcPortListWidget->selectedItems();
                for(const QListWidgetItem *srcPort : std::as_const(tempSrcPort))
                {
                    selectedSrcPortSet.insert(srcPort->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 1 || ui->filteringComboBox->currentIndex() == 4 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempDstPort = ui->dstPortListWidget->selectedItems();
                for(const QListWidgetItem *dstIp : std::as_const(tempDstPort))
                {
                    selectedDstPortSet.insert(dstIp->text());
                }
            }
            qDebug()<<"udp connected";
            // bool packetfileempty = false;
            if(ui->udporTcpComboBox->currentText() == "UDP")
            {
                emit createparseFilterPcapFile(0,ui->playUDPorTCPComboBox->currentIndex(),pcapFilePath,selectedSrcIpSet,selectedDstIpSet,selectedSrcPortSet,selectedDstPortSet);

            }
            else if(ui->udporTcpComboBox->currentText() == "TCP")
            {
                emit createparseFilterPcapFile(1,ui->playUDPorTCPComboBox->currentIndex(),pcapFilePath,selectedSrcIpSet,selectedDstIpSet,selectedSrcPortSet,selectedDstPortSet);

            }
        }
    }
}

void MainWindow::creatingTcpStatus(bool status)
{
    if(status == true)
    {
        // QMessageBox::information(this, "Success", "TCP Socket Created.");
    }
    else
    {
        // QMessageBox::information(this, "Fail", "Tcp Socket Not Created.");
    }
}

void MainWindow::creatingTcpServerStatus(bool status)
{
    if(status == true)
    {
        // QMessageBox::information(this, "Success", "TCP Server Creation Failed.");
    }
    else
    {
        // QMessageBox::information(this, "Fail", "Tcp Server Creation Failed.");
    }
}

void MainWindow::parseFilterPcapFileStatus(bool status)
{
    if(status == true)
    {
        ui->playerHorizontalSlider->setEnabled(true);
        ui->playerProgressBar->setEnabled(true);
        ui->playPushButton->setEnabled(true);
        ui->pausePushButton->setEnabled(true);
        ui->timerSpeedSpinBox->setEnabled(true);
    }
    else
    {
        QMessageBox::information(this, "INFO", "NO Filtered Packets found.");
        ui->playerHorizontalSlider->setEnabled(false);
        ui->playerProgressBar->setEnabled(false);
        ui->playPushButton->setEnabled(false);
        ui->pausePushButton->setEnabled(false);
        ui->timerSpeedSpinBox->setEnabled(false);
    }
}

void MainWindow::tcpConnectionStatus(bool tcpStatus)
{
    if(ui->udporTcpComboBox->currentIndex() == -1)
    {
        QMessageBox::information(this, "INFO", "Please select UDP or TCP.");
    }
    else
    {
        if(tcpStatus == true && ui->playUDPorTCPComboBox->currentText() == "TCP CLIENT")
        {
            bool packetfileempty = false;

            QSet<QString> selectedSrcIpSet;
            QSet<QString> selectedDstIpSet;
            QSet<QString> selectedSrcPortSet;
            QSet<QString> selectedDstPortSet;
            if(ui->filteringComboBox->currentIndex() == 2 || ui->filteringComboBox->currentIndex() == 5 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempSrcIP = ui->srcIpListWidget->selectedItems();
                for(const QListWidgetItem *srcIp : std::as_const(tempSrcIP))
                {
                    selectedSrcIpSet.insert(srcIp->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 3 || ui->filteringComboBox->currentIndex() == 5 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempDstIP = ui->dstIpListWidget->selectedItems();
                for(const QListWidgetItem *dstIp : std::as_const(tempDstIP))
                {
                    selectedDstIpSet.insert(dstIp->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 0 || ui->filteringComboBox->currentIndex() == 4 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempSrcPort = ui->srcPortListWidget->selectedItems();
                for(const QListWidgetItem *srcPort : std::as_const(tempSrcPort))
                {
                    selectedSrcPortSet.insert(srcPort->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 1 || ui->filteringComboBox->currentIndex() == 4 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempDstPort = ui->dstPortListWidget->selectedItems();
                for(const QListWidgetItem *dstIp : std::as_const(tempDstPort))
                {
                    selectedDstPortSet.insert(dstIp->text());
                }
            }
            if(ui->udporTcpComboBox->currentText() == "UDP")
            {
                emit createparseFilterPcapFile(0,ui->playUDPorTCPComboBox->currentIndex(),pcapFilePath,selectedSrcIpSet,selectedDstIpSet,selectedSrcPortSet,selectedDstPortSet);

            }
            else if(ui->udporTcpComboBox->currentText() == "TCP")
            {
                emit createparseFilterPcapFile(1,ui->playUDPorTCPComboBox->currentIndex(),pcapFilePath,selectedSrcIpSet,selectedDstIpSet,selectedSrcPortSet,selectedDstPortSet);

            }

        }
        else if(tcpStatus == false && ui->playUDPorTCPComboBox->currentText() == "TCP CLIENT")
        {
            ui->playerHorizontalSlider->setEnabled(false);
            ui->playerProgressBar->setEnabled(false);
            ui->playPushButton->setEnabled(false);
            ui->pausePushButton->setEnabled(false);
            ui->timerSpeedSpinBox->setEnabled(false);
        }
    }
}

void MainWindow::tcpServerConnectionStatus(bool tcpStatus)
{
    if(ui->udporTcpComboBox->currentIndex() == -1)
    {
        QMessageBox::information(this, "Success", "Please select UDP or TCP.");
    }
    else
    {
        if(tcpStatus == true && ui->playUDPorTCPComboBox->currentText() == "TCP SERVER")
        {
            bool packetfileempty = false;


            QSet<QString> selectedSrcIpSet;
            QSet<QString> selectedDstIpSet;
            QSet<QString> selectedSrcPortSet;
            QSet<QString> selectedDstPortSet;
            if(ui->filteringComboBox->currentIndex() == 2 || ui->filteringComboBox->currentIndex() == 5 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempSrcIP = ui->srcIpListWidget->selectedItems();
                for(const QListWidgetItem *srcIp : std::as_const(tempSrcIP))
                {
                    selectedSrcIpSet.insert(srcIp->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 3 || ui->filteringComboBox->currentIndex() == 5 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempDstIP = ui->dstIpListWidget->selectedItems();
                for(const QListWidgetItem *dstIp : std::as_const(tempDstIP))
                {
                    selectedDstIpSet.insert(dstIp->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 0 || ui->filteringComboBox->currentIndex() == 4 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempSrcPort = ui->srcPortListWidget->selectedItems();
                for(const QListWidgetItem *srcPort : std::as_const(tempSrcPort))
                {
                    selectedSrcPortSet.insert(srcPort->text());
                }
            }
            if(ui->filteringComboBox->currentIndex() == 1 || ui->filteringComboBox->currentIndex() == 4 || ui->filteringComboBox->currentIndex() == 6)
            {
                QList<QListWidgetItem*> tempDstPort = ui->dstPortListWidget->selectedItems();
                for(const QListWidgetItem *dstIp : std::as_const(tempDstPort))
                {
                    selectedDstPortSet.insert(dstIp->text());
                }
            }
            if(ui->udporTcpComboBox->currentText() == "UDP")
            {
                emit createparseFilterPcapFile(0,ui->playUDPorTCPComboBox->currentIndex(),pcapFilePath,selectedSrcIpSet,selectedDstIpSet,selectedSrcPortSet,selectedDstPortSet);

            }
            else if(ui->udporTcpComboBox->currentText() == "TCP")
            {
                emit createparseFilterPcapFile(1,ui->playUDPorTCPComboBox->currentIndex(),pcapFilePath,selectedSrcIpSet,selectedDstIpSet,selectedSrcPortSet,selectedDstPortSet);

            }

        }
        else if(tcpStatus == false && ui->playUDPorTCPComboBox->currentText() == "TCP SERVER")
        {
            ui->playerHorizontalSlider->setEnabled(false);
            ui->playerProgressBar->setEnabled(false);
            ui->playPushButton->setEnabled(false);
            ui->pausePushButton->setEnabled(false);
            ui->timerSpeedSpinBox->setEnabled(false);
        }
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
        emit setStartorstopthePackets(checked);
    }
    else
    {
        qDebug()<<"stop";
        ui->playPushButton->setText("Play");
        ui->playPushButton->setChecked(false);
        ui->pausePushButton->setText("Pause");
        ui->pausePushButton->setChecked(false);
        emit setStartorstopthePackets(checked);
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
            emit setPausethePackets(checked);
        }
        else
        {
            ui->pausePushButton->setText("Pause");
            ui->pausePushButton->setChecked(false);
            emit setPausethePackets(checked);
        }
    }
}


void MainWindow::on_timerSpeedSpinBox_valueChanged(int arg1)
{
    qDebug()<<ui->timerSpeedSpinBox->value();
    emit setTimerSpeed(arg1);
}


void MainWindow::on_timerSpeedSpinBox_textChanged(const QString &arg1)
{
    qDebug()<<ui->timerSpeedSpinBox->value();

    emit setTimerSpeed(arg1.toInt());
}


void MainWindow::on_playerHorizontalSlider_sliderMoved(int position)
{
    qDebug()<<"position";
    emit setUICurrIndexwithSlider(position);
}


void MainWindow::on_playerHorizontalSlider_sliderPressed()
{
    qDebug()<<"position";

    emit setUICurrIndexwithSlider(ui->playerHorizontalSlider->value());
}
