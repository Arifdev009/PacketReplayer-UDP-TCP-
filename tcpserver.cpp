#include "tcpserver.h"

TcpServer::TcpServer(QObject *parent) : QObject(parent), m_server(new QTcpServer(this))
{
    connect(m_server, &QTcpServer::newConnection, this, &TcpServer::onNewConnection);
    connect(m_server, &QTcpServer::acceptError, this, &TcpServer::onErrorOccurred);
}

TcpServer::~TcpServer()
{
    stopServer();
}

void TcpServer::startServer(quint16 port)
{
    if (!m_server->isListening()) {
        if (m_server->listen(QHostAddress::Any, port))
        {
            qDebug()<<"server started";
            // Server started successfully
        } else
        {
            emit errorOccurred(m_server->errorString());
        }
    }
}

void TcpServer::stopServer() {
    // Disconnect all existing clients first
    for (QTcpSocket *client : std::as_const(m_clients))
    {
        client->disconnectFromHost();
        client->deleteLater();
    }
    m_clients.clear();

    if (m_server->isListening()) {
        m_server->close();
    }
}

bool TcpServer::isListening() const {
    return m_server->isListening();
}

void TcpServer::onNewConnection() {
    // Get the socket for the new connection
    QTcpSocket *clientSocket = m_server->nextPendingConnection();

    if (clientSocket)
    {
        // Setup connections for this specific client
        connect(clientSocket, &QTcpSocket::readyRead, this, &TcpServer::onReadyRead);
        connect(clientSocket, &QTcpSocket::disconnected, this, &TcpServer::onDisconnected);
        connect(clientSocket, &QTcpSocket::errorOccurred, this, &TcpServer::onErrorOccurred);

        if(m_clients.isEmpty())
        {
            emit connectionStatusChanged(true);
        }

        m_clients.append(clientSocket);
        emit clientConnected(clientSocket);
    }
}

void TcpServer::onReadyRead() {
    // Identify which socket sent the data
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (client) {
        QByteArray data = client->readAll();
        emit dataReceived(client, data);
    }
}

void TcpServer::onDisconnected()
{
    QTcpSocket *client = qobject_cast<QTcpSocket*>(sender());
    if (client)
    {
        m_clients.removeAll(client);
        emit clientDisconnected(client);
        client->deleteLater(); // Clean up memory
    }
    if(m_clients.isEmpty())
    {
        emit connectionStatusChanged(false);
    }
}

void TcpServer::broadcastData(const QByteArray &data) {
    for (QTcpSocket *client : std::as_const(m_clients))
    {
        if (client->state() == QAbstractSocket::ConnectedState)
        {
            client->write(data);
        }
    }
}

void TcpServer::sendToClient(QTcpSocket *client, const QByteArray &data) {
    if (client && client->state() == QAbstractSocket::ConnectedState) {
        client->write(data);
    }
}

void TcpServer::onErrorOccurred(QAbstractSocket::SocketError socketError)
{
    emit errorOccurred(m_server->errorString());
}
