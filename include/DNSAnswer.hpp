/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef DNSA_HPP
#define DNSA_HPP

#include "Helper.hpp"
#include <string.h>
#include <arpa/inet.h>

class Answer {
    // Class for storing and parsing answer, authority and additional section of DNS packet
private:
    std::string name;
    uint16_t dnstype;
    uint16_t dnsclass;
    uint32_t ttl;
    uint16_t datalength;
    std::string data;

public:
    Answer(char *buffer, int &offset) {
        // Constructor for parsing from buffer
        Helper helper;
        setName(helper.get_DN(buffer, offset));

        memcpy(&this->dnstype, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setDnsType(ntohs(this->getDnsType()));

        memcpy(&this->dnsclass, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setDnsClass(ntohs(this->getDnsClass()));

        memcpy(&this->ttl, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        this->setTtl(ntohl(this->getTtl()));

        memcpy(&this->datalength, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setDataLength(ntohs(this->getDataLength()));

        this->setData(get_answer_data(buffer, offset));
    }

    void PrintAnswer() {
        Helper helper;
        std::cout << this->getName() << ", ";
        helper.PrintQuestionType_Class(this->getDnsType(), this->getDnsClass());
        std::cout << ", " << this->getTtl() << ", ";
        std::cout << this->getData() << std::endl;
    }

    std::string getName() const {
        return name;
    }

    uint16_t getDnsType() const {
        return dnstype;
    }

    uint16_t getDnsClass() const {
        return dnsclass;
    }

    uint32_t getTtl() const {
        return ttl;
    }

    uint16_t getDataLength() const {
        return datalength;
    }

    std::string getData() const {
        return data;
    }

private:
    std::string get_answer_data(char *buffer, int &offset) {
        // Function for parsing data section capable of parsing IPv4, IPv6, domain name
        Helper helper;
        std::string ret;

        if ((this->getDnsType() == 1) && (this->getDataLength() == 4)) {
            ret = std::to_string(((int) buffer[offset] < 0) ? ((int) buffer[offset] + 256) : (int) buffer[offset]) + "."
                  + std::to_string(
                    ((int) buffer[offset + 1] < 0) ? ((int) buffer[offset + 1] + 256) : (int) buffer[offset + 1]) + "."
                  + std::to_string(
                    ((int) buffer[offset + 2] < 0) ? ((int) buffer[offset + 2] + 256) : (int) buffer[offset + 2]) + "."
                  + std::to_string(
                    ((int) buffer[offset + 3] < 0) ? ((int) buffer[offset + 3] + 256) : (int) buffer[offset + 3]);

            offset += 4;

        } else if ((this->getDnsType() == 28) && (this->getDataLength() == 16)) {
            char ipv6_str[INET6_ADDRSTRLEN];
            struct in6_addr ipv6_address;

            memcpy(&ipv6_address, &buffer[offset], 16);

            if (inet_ntop(AF_INET6, &ipv6_address, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
                ret = ipv6_str;

            } else {
                std::cerr << "Failed to convert IPv6 address." << std::endl;
            }
            offset += 16;

        } else if ((this->getDnsType() == 5) || (this->getDnsType() == 2) || (this->getDnsType() == 12)) {
            ret = helper.get_DN(buffer, offset);

        } else if (this->getDnsType() == 6) {
            ret = get_SOA_data(buffer, offset);
        } else {
            std::cerr << "Error while decoding data section: invalid data format" << std::endl;
        }

        return ret;
    }

    std::string get_SOA_data(char *buffer, int &offset) {
        Helper helper;
        std::string ret;

        ret += "MNAME: ";
        ret += helper.get_DN(buffer, offset);
        ret += ", RNAME: ";
        ret += helper.get_DN(buffer, offset);


        uint32_t serial;
        uint32_t refresh;
        uint32_t retry;
        uint32_t expire;
        uint32_t minimum;

        memcpy(&serial, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&refresh, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&retry, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&expire, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);
        memcpy(&minimum, buffer + offset, sizeof(uint32_t));
        offset += sizeof(uint32_t);


        serial = ntohl(serial);
        refresh = ntohl(refresh);
        retry = ntohl(retry);
        expire = ntohl(expire);
        minimum = ntohl(minimum);

        ret += ", SERIAL: ";
        ret += std::to_string(serial);
        ret += ", REFRESH: ";
        ret += std::to_string(refresh);
        ret += ", RETRY: ";
        ret += std::to_string(retry);
        ret += ", EXPIRE: ";
        ret += std::to_string(expire);
        ret += ", MINIMUM: ";
        ret += std::to_string(minimum);

        return ret;
    }

    void setName(const std::string &newName) {
        name = newName;
    }

    void setDnsType(uint16_t newDnsType) {
        dnstype = newDnsType;
    }

    void setDnsClass(uint16_t newDnsClass) {
        dnsclass = newDnsClass;
    }

    void setTtl(uint32_t newTtl) {
        ttl = newTtl;
    }

    void setDataLength(uint16_t newDataLength) {
        datalength = newDataLength;
    }

    void setData(const std::string &newData) {
        data = newData;
    }

};

#endif //DNSA_HPP