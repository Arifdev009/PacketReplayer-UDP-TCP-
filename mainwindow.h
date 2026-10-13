#ifndef MAINWINDOW_H
#define MAINWINDOW_H

#include <QMainWindow>
#include <QDebug>
#include <QUdpSocket>
#include <QHostAddress>
#include <QTcpSocket>
#include <QFileDialog>
#include <Qthread>
#include <QMessageBox>
#include <QListWidget>
#include <QNetworkInterface>

#include "pcapfileparser.h"
#include "packetplayer.h"


QT_BEGIN_NAMESPACE
namespace Ui { class MainWindow; }
QT_END_NAMESPACE

class MainWindow : public QMainWindow
{
    Q_OBJECT

public:
    MainWindow(QWidget *parent = nullptr);
    ~MainWindow();

private slots:
    void on_browsePushButton_clicked();

    void on_filteringComboBox_currentIndexChanged(int index);

    void on_srcIpListWidget_itemClicked(QListWidgetItem *item);

    void on_dstIpListWidget_itemClicked(QListWidgetItem *item);

    void on_srcPortListWidget_itemClicked(QListWidgetItem *item);

    void on_dstPortListWidget_itemClicked(QListWidgetItem *item);

    void on_udporTcpComboBox_currentIndexChanged(int index);

    void on_DstIPLineEdit_editingFinished();

    void on_playUDPorTCPComboBox_currentIndexChanged(int index);


    void on_playPushButton_clicked(bool checked);

    void on_pausePushButton_clicked(bool checked);
\

    void on_connectUDPTCPPushButton_clicked();

    void tcpConnectionStatus(bool tcpStatus);

    void tcpServerConnectionStatus(bool tcpStatus);

    void on_timerSpeedSpinBox_valueChanged(int arg1);

    void on_timerSpeedSpinBox_textChanged(const QString &arg1);

    void on_playerHorizontalSlider_sliderMoved(int position);

    void on_playerHorizontalSlider_sliderPressed();


    void creatingUdpStatus(bool status);
    void creatingTcpStatus(bool status);
    void creatingTcpServerStatus(bool status);

    void parseFilterPcapFileStatus(bool status);

private:
    Ui::MainWindow *ui;
    QString pcapFilePath;
    PcapFileParser *pcapfileparser;
    QThread *pcapFileParserThread;

    QMap<QString, QSet<QString>>  mapUdpIptoIP;
    QMap<QString, QSet<QString>>  mapUdpPorttoPort;
    QMap<QString, QSet<QString>>  mapUdpIpcomboSrcPort;
    QMap<QString, QSet<QString>>  mapUdpIpSrcPortComboDstCombo;
    // QSet<QString> qsetUdpSrcIp;
    // QSet<QString> qsetUdpDstIp;
    // QSet<QString> qsetUdpSrcPort;
    // QSet<QString> qsetUdpDstPort;

    QMap<QString, QSet<QString>>  mapTcpIptoIP;
    QMap<QString, QSet<QString>>  mapTcpPorttoPort;
    QMap<QString, QSet<QString>>  mapTcpIpcomboSrcPort;
    QMap<QString, QSet<QString>>  mapTcpIpSrcPortComboDstCombo;
    // QSet<QString> qsetTcpSrcIp;
    // QSet<QString> qsetTcpDstIp;
    // QSet<QString> qsetTcpSrcPort;
    // QSet<QString> qsetTcpDstPort;

    QStringList udpSrcPortList;
    QStringList udpSrcIpList;
    QStringList tcpSrcPortList;
    QStringList tcpSrcIpList;

    QStringList udpDstPortList;
    QStringList udpDstIpList;
    QStringList tcpDstPortList;
    QStringList tcpDstIplist;

    QStringList srcIpList;
    QStringList dstIpList;
    QStringList srcPortList;
    QStringList dstPortList;

    QString selectedsrcIP;
    QString selecteddstIp;
    QString selectedsrcPort;
    QString selecteddstPort;


    QHostAddress dstIpAddress;
    QHostAddress srcIpAddress;
    QString srcPort;
    QString dstPort;

    packetPlayer *packetplayer;
    QThread *packetplayerThread;

signals:
    void startorstopthePlayer(bool startorstop);
    void pauseorresumethePlayer(bool pauseorresume);

    void startParsing(QString filepath);

    void setTimerSpeed(unsigned int timerSpeed);
    void setPausethePackets(bool pauseorResume);
    void setStartorstopthePackets(bool startorstop);
    void setUICurrIndexwithSlider(unsigned int percent);

    void createparseFilterPcapFile(bool udportcp,unsigned int sendingudportcp,QString pcapFilePath, QSet<QString> srcIpAddress, QSet<QString> dstIpAddress, QSet<QString> srcPort, QSet<QString> dstPort);


    void setCreateUDP(QHostAddress srcIpAddress, QHostAddress dstIpAddress, QString srcPort, QString dstPort);
    void setCreateTcp(QHostAddress srcIpAddress, QHostAddress dstIpAddress, QString srcPort, QString dstPort);
    void setCreateTcpServer(QHostAddress srcIpAddress, QHostAddress dstIpAddress, QString srcPort, QString dstPort);

};
#endif // MAINWINDOW_H
