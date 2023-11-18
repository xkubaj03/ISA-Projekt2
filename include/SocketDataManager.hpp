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
    struct sockaddr_in serverV4;
    struct sockaddr_in6 serverV6;
    int sock;
    ssize_t sent_bytes;
    ssize_t bytes_received;

public:
    char sendBuffer[BUFFER];
    int sendOffset = 0;
    char recvBuffer[BUFFER];
    int recvOffset = 0;

    explicit SocketDataManager(Parameters param) {
        Helper helper;
        sockaddr_storage addressInfo;
        std::string resolvedIP = helper.getSIP(param.getSParam(), addressInfo);

        setSock(socket(addressInfo.ss_family, SOCK_DGRAM, 0));
        if (getSock() == -1) {
            std::cerr << "socket() failed\n";
            exit(1);
        }

        if (addressInfo.ss_family == AF_INET) {
            this->serverV4.sin_port = htons(param.getPParam());
            this->serverV4.sin_family = AF_INET;
            this->serverV4.sin_addr.s_addr = inet_addr(resolvedIP.c_str());
        } else if (addressInfo.ss_family == AF_INET6) {
            this->serverV6.sin6_port = htons(param.getPParam());
            this->serverV6.sin6_family = AF_INET6;

            if (inet_pton(AF_INET6, resolvedIP.c_str(), &this->serverV6.sin6_addr) <= 0) {
                std::cerr << "Failed to convert IPv6 Address" << std::endl;
                exit(1);
            }
        } else {
            std::cerr << "Unknown address family" << std::endl;
            exit(1);
        }
    }

    void Send() {
        if(serverV4.sin_family == AF_INET) {
            setSentBytes(
                    sendto(
                            sock,
                            sendBuffer,
                            sendOffset,
                            0,
                            (struct sockaddr *) &serverV4,
                            sizeof(serverV4))
            );
        }else {
            setSentBytes(
                    sendto(
                            sock,
                            sendBuffer,
                            sendOffset,
                            0,
                            (struct sockaddr *) &serverV6,
                            sizeof(serverV6))
            );
        }

        if (getSentBytes() < 0) {
            std::cerr << "Chyba při odesílání DNS packetu sendto: "<< getSentBytes() << std::endl;
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