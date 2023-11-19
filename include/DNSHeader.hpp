/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef DNSQ_HPP
#define DNSQ_HPP

#include "Param.hpp"
#include <cstring>     //string
#include <arpa/inet.h>

class Header {
    // Class for storing and parsing header section of DNS packet
private:
    uint16_t id;        /* ID number */
    uint16_t flags;     /* Bit flags */
    uint16_t qdcount;   /* question count */
    uint16_t ancount;   /* answer count */
    uint16_t nscount;   /* authority count */
    uint16_t arcount;   /* additional count */

    Header(Header *header) {
        // Constructor for temporary instance of Header class that is used for parsing
        setId(htons(header->getId()));
        setFlags(htons(header->getFlags()));
        setQdCount(htons(header->getQdCount()));
        setAnCount(htons(header->getAnCount()));
        setNsCount(htons(header->getNsCount()));
        setArCount(htons(header->getArCount()));
    }

public:
    Header(Parameters param) {
        // Constructor for creating header for sending
        setId(0x1234);

        int16_t flags = 0x0000;
        if (param.getRParam()) {
            flags |= (1 << 8);
        }

        this->setFlags(flags);
        this->setQdCount(1);
        this->setAnCount(0);
        this->setNsCount(0);
        this->setArCount(0);
    }

    Header(char *buffer, int &offset, ssize_t bytesReceived) {
        // Constructor for parsing header from buffer
        if((long int)(offset + sizeof(Header)) > bytesReceived) {
            std::cerr << "Not enough data to recieve DNS header" << std::endl;
            exit(1);
        }

        memcpy(&this->id, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setId(ntohs(this->getId()));

        memcpy(&this->flags, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setFlags(ntohs(this->getFlags()));

        memcpy(&this->qdcount, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setQdCount(ntohs(this->getQdCount()));

        memcpy(&this->ancount, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setAnCount(ntohs(this->getAnCount()));

        memcpy(&this->nscount, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setNsCount(ntohs(this->getNsCount()));

        memcpy(&this->arcount, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setArCount(ntohs(this->getArCount()));
    }

    void ParseHeaderInBuffer(char *buffer, int &offset) {
        Header header(this);
        memcpy(&buffer[offset], &header, sizeof(Header));
        offset += sizeof(Header);
    }

    void printDNSReplyCode() {
        switch (this->flags & 0x000F) {
            case 1:
                std::cerr << "Format error: The query has a format error." << std::endl;
                break;
            case 2:
                std::cerr << "Server failure: The DNS server encountered a failure." << std::endl;
                break;
            case 3:
                std::cerr << "Name error: The domain name does not exist." << std::endl;
                break;
            case 4:
                std::cerr << "Not Implemented: The DNS server does not support the requested query." << std::endl;
                break;
            case 5:
                std::cerr << "Refused: The DNS server refused to respond to the query." << std::endl;
                break;
        }
    }

    uint16_t getId() const { return id; }

    uint16_t getFlags() const { return flags; }

    uint16_t getQdCount() const { return qdcount; }

    uint16_t getAnCount() const { return ancount; }

    uint16_t getNsCount() const { return nscount; }

    uint16_t getArCount() const { return arcount; }

private:
    void setId(uint16_t id) { this->id = id; }

    void setFlags(uint16_t flags) { this->flags = flags; }

    void setQdCount(uint16_t qdcount) { this->qdcount = qdcount; }

    void setAnCount(uint16_t ancount) { this->ancount = ancount; }

    void setNsCount(uint16_t nscount) { this->nscount = nscount; }

    void setArCount(uint16_t arcount) { this->arcount = arcount; }
};

#endif //DNSQ_HPP