#ifndef TCPCLIENT_H
#define TCPCLIENT_H

#include <QObject>
#include <QTcpSocket>
#include <QHostAddress>

class TcpClient : public QObject {
    Q_OBJECT
public:
    explicit TcpClient(QObject *parent = nullptr);
    ~TcpClient();

    void connectToServer(const QString &host, quint16 port);
    void disconnectFromServer();
    void sendData(const QByteArray &data);
    bool isConnected() const;

signals:
    void dataReceived(const QByteArray &data);
    void connectionStatusChanged(bool connected);
    void errorOccurred(const QString &errorStr);

private slots:
    void onReadyRead();
    void onConnected();
    void onDisconnected();
    void onErrorOccurred(QAbstractSocket::SocketError socketError);

public:
    QTcpSocket *m_socket;
};

#endif // TCPCLIENT_H
