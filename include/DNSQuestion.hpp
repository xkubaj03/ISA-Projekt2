/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */

#include "Param.hpp"
#include "Helper.hpp"
#include <arpa/inet.h>  //inet_addr

class Question {
    // Class for storing and parsing question section of DNS packet
private:
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;    /* The QCLASS (1 = IN) */

    explicit Question(Question *question) {
        // Constructor for temporary instance of Question class that is used for parsing
        setQname(encodeDN_IPv4_Ipv6(question->getQname()));
        setQname((this->getQname().substr(0, this->getQname().length())));
        setQtype(htons(question->getQtype()));
        setQclass(htons(question->getQclass()));
    }

public:
    explicit Question(Parameters param) {
        // Constructor for creating question for sending
        setQclass(1);   /* QCLASS 1=IN */
        setQtype(1);    /* QTYPE 1=A */

        if (param.getA6Param()) {
            setQtype(28); /* QTYPE 28=AAAA */
        }

        if (param.getXParam()) {
            setQtype(12); /* QTYPE 12=PTR */
            setQname(ReverseIP(param.getAddressParam()));

        } else {
            setQname(param.getAddressParam());
        }
    }

    Question(char *buffer, int &offset) {
        // Constructor for parsing question from buffer
        Helper helper;
        setQname(helper.get_DN(buffer, offset));

        memcpy(&this->qtype, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setQtype(ntohs(this->getQtype()));

        memcpy(&this->qclass, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setQclass(ntohs(this->getQclass()));
    }

    void ParseQuestionInBuffer(char *buffer, int &offset) {
        Question question(this);

        int len = question.getQname().length()+1;

        if (this->getQtype() == 12 && len < 32) {
            len--;
        }

        memcpy(&buffer[offset], question.getQname().c_str(), len);
        offset += len;

        memcpy(&buffer[offset], &question.qtype, sizeof(uint16_t));
        offset += sizeof(uint16_t);

        memcpy(&buffer[offset], &question.qclass, sizeof(uint16_t));
        offset += sizeof(uint16_t);
    }

    void PrintQuestion() {
        Helper helper;
        std::cout << "Question section(1)" << std::endl;
        std::cout << this->getQname() << ", ";
        helper.PrintQuestionType_Class(this->getQtype(), this->getQclass());
        std::cout << std::endl;
    }

    std::string getQname() {
        return this->qname;
    }

    uint16_t getQtype() {
        return this->qtype;
    }

    uint16_t getQclass() {
        return this->qclass;
    }

private:
    int checkIPAddressType(const std::string &input) {
        struct in_addr ipv4Addr;
        struct in6_addr ipv6Addr;

        if (inet_pton(AF_INET, input.c_str(), &ipv4Addr) == 1) {
            return AF_INET;
        }

        if (inet_pton(AF_INET6, input.c_str(), &ipv6Addr) == 1) {
            return AF_INET6;
        }

        return 0;
    }

    std::string expandAndReverseIPv6Address(std::string address) {
        // This method was created by Chat GPT 3.5 (with some modifications)
        struct in6_addr addr;
        if (inet_pton(AF_INET6, address.c_str(), &addr) != 1) {
            return "Invalid IPv6 address";
        }

        std::stringstream expanded;
        expanded << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) {
            expanded << std::setw(4) << ntohs(addr.s6_addr16[i]);
        }

        std::string ret = expanded.str();
        int n = ret.length();

        for (int i = 0; i < n / 2; i++) {
            std::swap(ret[i], ret[n - i - 1]);
        }

        ret.append(".ip6.arpa.");

        return ret;
    }

    std::string reverseIPv4Address(std::string address) {
        Helper helper;
        sockaddr_storage addr;
        address = helper.getSIP(address, addr);
        std::string ret;

        int pos;
        for (int i = 0; i < 3; i++) {
            pos = address.rfind('.');
            ret.append(address, pos + 1);
            ret.append(".");
            address = address.substr(0, pos);
        }
        ret.append(address);
        ret.append(".in-addr.arpa.");
        return ret;
    }

    std::string encodeIPv6(std::string input) {
        std::string ret;

        for(uint i = 0; i < 32; i++) {
            ret += "\001";
            ret += input[i];
        }
        ret += "\003ip6\004arpa\000";

        return ret;
    }

    std::string encodeDN_IPv4_Ipv6(std:: string input) {
        if(input.length() == 42) {
            return encodeIPv6(input);
        }

        return encodeDN_IPv4(input);
    }

    std::string encodeDN_IPv4(std::string hostname) {
        hostname = "." + hostname;

        int dot = 0;
        int next_dot = 1;

        while (hostname[next_dot] != 0) {
            if (hostname[next_dot] != '.') {
                next_dot++;

            } else {
                hostname[dot] = next_dot - dot - 1;
                dot = next_dot++;
            }
        }

        hostname[dot] = hostname.length() - dot - 1;

        return hostname;
    }

    std::string ReverseIP(std::string address) {
        int type = checkIPAddressType(address);
        if (type == 0) {
            std::cerr << "Invalid IP querry address" << std::endl;
            exit(1);
        }

        if (type == AF_INET) {
            return reverseIPv4Address(address);
        }
        return expandAndReverseIPv6Address(address);
    }

    void setQname(std::string qname) {
        this->qname = qname;
    }

    void setQtype(uint16_t qtype) {
        this->qtype = qtype;
    }

    void setQclass(uint16_t qclass) {
        this->qclass = qclass;
    }
};