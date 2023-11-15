/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */

#include "Param.hpp"
#include <arpa/inet.h>  //inet_addr

class Question {
private:
    std::string qname;
    uint16_t qtype;
    uint16_t qclass;    /* The QCLASS (1 = IN) */

    explicit Question (Question *question) {
        Helper helper;
        setQname(helper.encodeDirect(question->getQname()));
        setQname((this->getQname().substr(0, this->getQname().length())));
        setQtype(htons(question->getQtype()));
        setQclass(htons(question->getQclass()));

        //std::cout << "Reverse: \"" << this->getQname() << "\"" << std::endl;
        //helper.printStringAsHex(this->getQname());
    }

public:
    explicit Question (Parameters param) {
        Helper helper;
        setQclass(1);   /* QCLASS 1=IN */
        setQtype(1);    /* QTYPE 1=A */

        if(param.getA6Param()) {
            setQtype(28); /* QTYPE 28=AAAA */
        }

        if(param.getXParam()) {
            setQtype(12); /* QTYPE 12=PTR */
            setQname(helper.reverseDN(param.getAddressParam()));

        }else {
            setQname(param.getAddressParam());
        }
    }

    Question (char* buffer, int& offset) {
        Helper helper;
        setQname(helper.get_DN(buffer, offset));

        memcpy(&this->qtype, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setQtype(ntohs(this->getQtype()));

        memcpy(&this->qclass, buffer + offset, sizeof(uint16_t));
        offset += sizeof(uint16_t);
        this->setQclass(ntohs(this->getQclass()));
    }

    void ParseQuestionInBuffer (char* buffer, int& offset) {
        Question question(this);
        int len = question.getQname().length();

        if(this->getQtype() != 12) {
            len++;
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