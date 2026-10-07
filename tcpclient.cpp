#include "tcpclient.h"

TcpClient::TcpClient(QObject *parent) : QObject(parent), m_socket(new QTcpSocket(this)) {
    connect(m_socket, &QTcpSocket::connected, this, &TcpClient::onConnected);
    connect(m_socket, &QTcpSocket::disconnected, this, &TcpClient::onDisconnected);
    connect(m_socket, &QTcpSocket::readyRead, this, &TcpClient::onReadyRead);
    connect(m_socket, &QTcpSocket::errorOccurred, this, &TcpClient::onErrorOccurred);
}

TcpClient::~TcpClient() {
    disconnectFromServer();
}

void TcpClient::connectToServer(const QString &host, quint16 port) {
    if (m_socket->state() == QAbstractSocket::UnconnectedState) {
        m_socket->connectToHost(host, port);
    }
}

void TcpClient::disconnectFromServer() {
    if (m_socket->isOpen()) {
        m_socket->disconnectFromHost();
    }
}

void TcpClient::sendData(const QByteArray &data) {
    if (m_socket->isOpen() && m_socket->isWritable()) {
        m_socket->write(data);
    }
}

bool TcpClient::isConnected() const {
    return m_socket->state() == QAbstractSocket::ConnectedState;
}

void TcpClient::onReadyRead() {
    QByteArray data = m_socket->readAll();
    emit dataReceived(data);
}

void TcpClient::onConnected() {
    emit connectionStatusChanged(true);
}

void TcpClient::onDisconnected() {
    emit connectionStatusChanged(false);
}

void TcpClient::onErrorOccurred(QAbstractSocket::SocketError socketError) {
    Q_UNUSED(socketError);
    emit errorOccurred(m_socket->errorString());
}
