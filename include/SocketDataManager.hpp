/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef DNSS_HPP
#define DNSS_HPP

#include "Param.hpp"

#include<sys/socket.h>  //socket
#include<unistd.h>      //close
#include<arpa/inet.h>   //inet_addr
#include<netinet/in.h>  //sockaddr_in

#define BUFFER 1024

class SocketDataManager {
private:
    struct sockaddr_in server;
    int sock;
    ssize_t sent_bytes;
    ssize_t bytes_received;

public:
    char sendBuffer[BUFFER];
    int sendOffset = 0;
    char recvBuffer[BUFFER];
    int recvOffset = 0;

    SocketDataManager(Parameters param) {
        Helper helper;
        setSock(socket(AF_INET, SOCK_DGRAM, 0));
        if (getSock() == -1) {
            std::cerr << "socket() failed\n";
            exit(1);
        }
    //TODO set server musí zvládnout IPV4,6 a DN
        setServer(inet_addr(helper.get_IPv4(param.getSParam()).c_str()),
                  AF_INET,
                  htons(param.getPParam())
        );
    }

    void Send() {
        setSentBytes(
                sendto(
                        sock,
                        sendBuffer,
                        sendOffset,
                        0,
                        (struct sockaddr *) &server,
                        sizeof(server))
        );

        if (getSentBytes() < 0) {
            std::cerr << "Chyba při odesílání DNS packetu" << std::endl;
            exit(1);
        }
    }

    void Recieve() {
        setBytesReceived(
                recvfrom(
                        sock,
                        recvBuffer,
                        sizeof(recvBuffer),
                        0,
                        NULL,
                        NULL)
        );

        if (getBytesReceived() < 0) {
            std::cerr << "Error while receiving data" << std::endl;
            close(getSock());
            exit(1);

        } else if (getBytesReceived() == 0) {
            std::cerr << "Remote end terminated the connection." << std::endl;
            close(getSock());
            exit(1);
        }

        close(sock);
    }

    ~SocketDataManager() {
        if (sock >= 0) {
            close(sock);
        }
    }

private:
    void setSock(int sock) {
        this->sock = sock;
    }

    void setSentBytes(ssize_t sent_bytes) {
        this->sent_bytes = sent_bytes;
    }

    void setBytesReceived(ssize_t bytes_received) {
        this->bytes_received = bytes_received;
    }

    void setServer(u_int s_addr, sa_family_t family, in_port_t port) {
        this->server.sin_addr.s_addr = s_addr;
        this->server.sin_family = family;
        this->server.sin_port = port;
    }


    int getSock() {
        return this->sock;
    }

    ssize_t getSentBytes() {
        return this->sent_bytes;
    }

public:
    ssize_t getBytesReceived() {
        return this->bytes_received;
    }

};

#endif //DNSS_HPP