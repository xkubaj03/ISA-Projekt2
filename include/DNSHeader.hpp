/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef DNSQ_HPP
#define DNSQ_HPP

#include "Param.hpp"
#include <arpa/inet.h>

class Header {
private:
    uint16_t id;        /* ID number */
    uint16_t flags;     /* Bit flags */
    uint16_t qdcount;   /* question count */
    uint16_t ancount;   /* answer count */
    uint16_t nscount;   /* authority count */
    uint16_t arcount;   /* additional count */

    Header(Header *header) {
        setId(htons(header->getId()));
        setFlags(htons(header->getFlags()));
        setQdCount(htons(header->getQdCount()));
        setAnCount(htons(header->getAnCount()));
        setNsCount(htons(header->getNsCount()));
        setArCount(htons(header->getArCount()));
    }

public:

    Header(Parameters param) {
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

    Header(char *buffer, int &offset) {
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