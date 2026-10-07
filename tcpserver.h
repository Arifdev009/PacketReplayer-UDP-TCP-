#ifndef TCPSERVER_H
#define TCPSERVER_H

#include <QObject>
#include <QTcpServer>
#include <QTcpSocket>
#include <QMap>

class TcpServer : public QObject {
    Q_OBJECT
public:
    explicit TcpServer(QObject *parent = nullptr);
    ~TcpServer();

    void startServer(quint16 port);
    void stopServer();
    void broadcastData(const QByteArray &data);
    void sendToClient(QTcpSocket *client, const QByteArray &data);
    bool isListening() const;

signals:
    void clientConnected(QTcpSocket *client);
    void clientDisconnected(QTcpSocket *client);
    void dataReceived(QTcpSocket *client, const QByteArray &data);
    void errorOccurred(const QString &errorStr);
    void connectionStatusChanged(bool connected);

private slots:
    void onNewConnection();
    void onReadyRead();
    void onDisconnected();
    void onErrorOccurred(QAbstractSocket::SocketError socketError);

private:
    QTcpServer *m_server;
    // Keep track of connected clients
    QList<QTcpSocket*> m_clients;
};

#endif // TCPSERVER_H
