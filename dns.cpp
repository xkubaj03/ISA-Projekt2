/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */

#include <iostream>
#include <getopt.h>


#include<stdio.h>
#include<string.h>
#include<sys/socket.h>
#include<arpa/inet.h>
#include<netinet/in.h>
#include<unistd.h>
#include<netdb.h>
#include<err.h>
#include <array>
#include <stdlib.h>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <iomanip>
#include <arpa/inet.h>
#include <cstdint>
#include <cstring>


struct Param {
    bool r_param = false;
    bool x_param = false;
    bool a6_param = false;
    std::string s_param;
    uint p_param = 53;
    std::string address_param;
};

struct dns_header {
    uint16_t id;        /* ID číslo */
    uint16_t flags;     /* Bitové vlajky DNS zprávy */
    uint16_t qdcount;   /* Počet dotazů v dotazové sekci */
    uint16_t ancount;   /* Počet záznamů v odpovědi sekci */
    uint16_t nscount;   /* Počet autoritativních záznamů v odpovědi sekci */
    uint16_t arcount;   /* Počet doplňujících záznamů v odpovědi sekci */
};

struct dns_question {
    std::string name;
    uint16_t dnstype;  /* The QTYPE (1 = A) */
    uint16_t dnsclass; /* The QCLASS (1 = IN) */
};

struct dns_answer {
    std::string name;       // Doménové jméno, na které byla odpověď nalezena
    uint16_t dnstype;       // Typ záznamu (např. A, AAAA, MX)
    uint16_t dnsclass;      // Třída záznamu (většinou IN pro Internet)
    uint32_t ttl;           // Doba platnosti (TTL)
    uint16_t datalength;    // Délka datového pole
    std::vector<uint8_t> data; // Skutečná data záznamu (změnlivá délka)
};

struct dns_authority {
    std::string name;         // Název (doména) autoritativního záznamu
    uint16_t type;            // Typ záznamu (např. NS)
    uint16_t dnsClass;        // Třída záznamu (např. IN)
    uint32_t ttl;             // TTL (čas života záznamu)
    std::vector<uint8_t> data; // Data autoritativního záznamu
};

struct dns_additional {
    std::string name;         // Název (doména) doplňujícího záznamu
    uint16_t type;            // Typ záznamu (např. A, AAAA)
    uint16_t dnsClass;        // Třída záznamu (např. IN)
    uint32_t ttl;             // TTL (čas života záznamu)
    std::vector<uint8_t> data; // Data doplňujícího záznamu
};

#define IP_ADDR "127.0.0.1"
#define BUFFER 1024
#define SBUFF 128

#define DEBUG 1

void printUsage() {
    std::cerr << "Usage: dns [-r] [-x] [-6] -s server [-p port] address" << std::endl;
}

void read_args(int argc, char *argv[], Param *ret) {
    int opt;
    while ((opt = getopt(argc, argv, "rx6s:p:")) != -1) {
        switch (opt) {
            case 'r':
                ret->r_param = true;
                break;
            case 'x':
                ret->x_param = true;
                break;
            case '6':
                ret->a6_param = true;
                break;
            case 's':
                ret->s_param = optarg;
                break;
            case 'p':
                if (std::stoi(optarg) < 0 || std::stoi(optarg) > 65535) {
                    std::cout << "Wrong port number! (0 - 65535)\n";
                    exit(0);
                }
                ret->p_param = std::stoi(optarg);
                break;
            default:
                std::cerr << "Unknown parameter: " << static_cast<char>(optopt) << std::endl;
                printUsage();
                exit(0);
        }
    }

    if (optind < argc) {
        ret->address_param = argv[optind];
    } else {
        std::cerr << "Missing targeted address!" << std::endl;
        printUsage();
        exit(0);
    }
    if (ret->s_param.empty()) {
        std::cerr << "Requiered parameter -s with argument" << std::endl;
        printUsage();
        exit(0);
    }
}

void printCharArrayAsHex(const char *array, std::size_t length) {
    for (std::size_t i = 0; i < length; ++i) {
        std::cout << std::hex << std::setw(2) << std::setfill('0')
                  << static_cast<int>(static_cast<unsigned char>(array[i])) << " ";
    }
    std::cout << std::dec << std::endl; // Nastaví zpět na desítkový formát
}

void printStringAsHex(const std::string &str) {
    for (char c: str) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(static_cast<unsigned char>(c))
                  << " ";
    }
    std::cout << std::dec << std::endl;
}

std::string getIP(std::string name) {
    struct hostent *host_info;

    host_info = gethostbyname(name.c_str());
    if (host_info == NULL) {
        std::cerr << "gethostbyname error" << std::endl;
        exit(1);
    }

    struct in_addr *ipv4_addr = (struct in_addr *) host_info->h_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipv4_addr, ip, INET_ADDRSTRLEN);

    return ip;
}

std::string encodeDirect(std::string hostname) {
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
    if (0) {
        std::cout << "Encoded: ";
        printStringAsHex(hostname);
        std::cout << std::endl;
    }

    return hostname;
}

std::string encodeReverse(std::string hostname) {
    hostname = getIP(hostname);
    std::string ret;

    int pos;
    for (int i = 0; i < 3; i++) {
        pos = hostname.rfind('.');
        ret.append(hostname, pos+1);
        ret.append(".");
        hostname = hostname.substr(0, pos);
    }
    ret.append(hostname);
    ret.append(".in-addr.arpa.");
    return ret;
}

void create_dns_packet(Param parameters, char* buffer, int& offset) {
    //TODO IPv4 done IPv6 not done
    dns_header header{};
    header.id = htons(0x1234);

    int16_t flags = 0x0000;
    if (parameters.r_param) {
        flags |= (1 << 8);
    }
    if (parameters.x_param) {
        flags |= (1 << 7);
    }
    header.flags = htons(flags);
    header.qdcount = htons(1);
    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);

    memcpy(&buffer[offset], &header, sizeof(dns_header));
    offset += sizeof(dns_header);

    dns_question question;
    question.dnstype = htons(1);  /* QTYPE 1=A */

    if (parameters.a6_param)
        question.dnstype = htons(28); /* QTYPE 28=AAAA */

    if (parameters.x_param) {
        question.name = encodeDirect(encodeReverse(parameters.address_param));
        question.name = question.name.substr(0, question.name.length() - 1);
        question.dnstype = htons(12); /* QTYPE 12=PTR */
    } else {
        question.name = encodeDirect(parameters.address_param);
    }

    question.dnsclass = htons(1); /* QCLASS 1=IN */

    memcpy(&buffer[offset], question.name.c_str(), question.name.length() + 1);
    offset += question.name.length() + 1;

    memcpy(&buffer[offset], &question.dnstype, sizeof(question.dnstype));
    offset += sizeof(question.dnstype);

    memcpy(&buffer[offset], &question.dnsclass, sizeof(question.dnsclass));
    offset += sizeof(question.dnsclass);

}

void get_header(dns_header& header, char* buffer, int& offset) {
    memcpy(&header, buffer + offset, sizeof(dns_header));
    memcpy(&header, buffer, sizeof(dns_header));
    header.id = ntohs(header.id);
    header.flags = ntohs(header.flags);
    header.qdcount = ntohs(header.qdcount);
    header.ancount = ntohs(header.ancount);
    header.nscount = ntohs(header.nscount);
    header.arcount = ntohs(header.arcount);
    offset += sizeof(dns_header);
}

void printHeaderInfo(dns_header header){
    std::cout << "Authoritative: ";
    if (header.flags & (1 << 10)) {
        std::cout << "Yes";
    } else {
        std::cout << "No";
    }
    std::cout << ", Recursive: ";
    if (header.flags & (1 << 8)) {
        std::cout << "Yes";
    } else {
        std::cout << "No";
    }
    std::cout << ", Truncated: ";
    if (header.flags & (1 << 9)) {
        std::cout << "Yes" << std::endl;
    } else {
        std::cout << "No" << std::endl;
    }
}

std::string get_DN(char* buffer, int& offset){
    int tmp = offset;
    char *nullTerminator = strchr(buffer + offset, '\0');
    int nullIndex = nullTerminator - buffer;

    char recieved_question_name[SBUFF];

    memcpy(&recieved_question_name, buffer + offset, nullIndex);
    recieved_question_name[nullIndex - tmp] = '\0';
    recieved_question_name[0] = ' ';
    for (int i = 1; (i < nullIndex) && (recieved_question_name[i] != '\0'); i++) {
        if (recieved_question_name[i] < 46) {
            recieved_question_name[i] = '.';
        }
    }
    offset = nullIndex + 1;

    return recieved_question_name;
}
void get_question(dns_question& question, char* buffer, int& offset) {
    question.name = get_DN(buffer, offset);
    memcpy(&question.dnstype, buffer + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    memcpy(&question.dnsclass, buffer + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);

    question.dnstype = ntohs(question.dnstype);
    question.dnsclass = ntohs(question.dnsclass);
}

void get_answer(dns_answer& answer, char* buffer, int& offset) {
    uint16_t pointer;
    memcpy(&pointer, buffer + offset, sizeof(uint16_t));
    pointer = ntohs(pointer);

    if (pointer >> 14 == 3) {
        int tmp = offset;
        offset = (pointer & 0x3FFF);

        answer.name = get_DN(buffer, offset);

        offset = tmp + 2;

    }else {
        answer.name = get_DN(buffer, offset);
    }

    memcpy(&answer.dnstype, buffer + offset, sizeof(uint16_t));
    answer.dnstype = ntohs(answer.dnstype);
    offset += sizeof(uint16_t);

    memcpy(&answer.dnsclass, buffer + offset, sizeof(uint16_t));
    answer.dnsclass = ntohs(answer.dnsclass);
    offset += sizeof(uint16_t);

    memcpy(&answer.ttl, buffer + offset, sizeof(uint32_t));
    offset += sizeof(uint32_t);
    answer.ttl = ntohl(answer.ttl);

    memcpy(&answer.datalength, buffer + offset, sizeof(uint16_t));
    offset += sizeof(uint16_t);
    answer.datalength = ntohs(answer.datalength);

}

void PrintQuestionType_Class(uint16_t dnstype, uint16_t dnsclass) {
    switch (dnstype) {
        case 1:
            std::cout << "A";
            break;
        case 2:
            std::cout << "NS";
            break;
        case 5:
            std::cout << "CNAME";
            break;
        case 6:
            std::cout << "SOA";
            break;
        case 12:
            std::cout << "PTR";
            break;
        case 15:
            std::cout << "MX";
            break;
        case 28:
            std::cout << "AAAA";
            break;
        default:
            std::cout << "Unknown";
            break;
    }
    if (dnsclass == 1) {
        std::cout << ", IN";
    } else {
        std::cout << ", Unknown";
    }
}

void PrintRecievedAddress(char* buffer, int& offset, uint16_t recieved_answer_data_length, uint16_t recieved_answer_type) {
    if(recieved_answer_type == 12) {
        //reversed search
        std::cout << get_DN(buffer, offset) << std::endl;

    } else if (recieved_answer_data_length == 4) {
        std::cout << std::dec << (((int)buffer[offset] < 0) ? ((int)buffer[offset] + 256) : (int)buffer[offset]) << ".";
        std::cout << std::dec << (((int)buffer[offset + 1] < 0) ? ((int)buffer[offset + 1] + 256) : (int)buffer[offset + 1]) << ".";
        std::cout << std::dec << (((int)buffer[offset + 2] < 0) ? ((int)buffer[offset + 2] + 256) : (int)buffer[offset + 2]) << ".";
        std::cout << std::dec << (((int)buffer[offset + 3] < 0) ? ((int)buffer[offset + 3] + 256) : (int)buffer[offset + 3]) << std::endl;
        offset += 4;
    } else if (recieved_answer_data_length == 16) {
        char ipv6_str[INET6_ADDRSTRLEN];
        struct in6_addr ipv6_address;

        // Kopírování 16 bytů IPv6 adresy do struktury
        memcpy(&ipv6_address, &buffer[offset], 16);

        // Převod IPv6 adresy na textový řetězec
        if (inet_ntop(AF_INET6, &ipv6_address, ipv6_str, INET6_ADDRSTRLEN) != NULL) {
            std::cout << ipv6_str << std::endl;
        } else {
            std::cerr << "Failed to convert IPv6 address." << std::endl;
        }
        offset += 16;
    } else {
        std::cerr << "Bad address length" << std::endl;
    }
}

int main(int argc, char **argv) {
    Param parameters;
    read_args(argc, argv, &parameters);

    char dns_packet[BUFFER];
    int offset = 0;

    create_dns_packet(parameters, dns_packet, offset);

    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        std::cerr << "socket() failed\n";
        exit(1);
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(getIP(parameters.s_param).c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(parameters.p_param);

    ssize_t sent_bytes = sendto(sock, dns_packet, offset, 0, (struct sockaddr *) &server, sizeof(server));
    if (sent_bytes < 0) {
        std::cerr << "Chyba při odesílání DNS packetu" << std::endl;
        exit(1);
    }

    //recieving
    char recievedBuffer[BUFFER];
    offset = 0;

    ssize_t bytes_received = recvfrom(sock, recievedBuffer, sizeof(recievedBuffer), 0, NULL, NULL);
    if (bytes_received < 0) {
        std::cerr << "Chyba při přijímání dat" << std::endl;
        close(sock);
        return 1;
    } else if (bytes_received == 0) {
        std::cerr << "Vzdálený konec ukončil spojení." << std::endl;
        close(sock);
        return 0;
    }
    close(sock);
    //std::cout << "Počet přijatých bytů je: " << bytes_received << std::endl;
    //printCharArrayAsHex(recievedBuffer, bytes_received);


    dns_header recieved_header {};
    get_header(recieved_header, recievedBuffer, offset);

    printHeaderInfo(recieved_header);

    dns_question recieved_question {};

    get_question(recieved_question, recievedBuffer, offset);

    std::cout << "Question section(1)" << std::endl;
    std::cout << recieved_question.name << ", ";

    PrintQuestionType_Class(recieved_question.dnstype, recieved_question.dnsclass);

    std::cout << std::endl;


    dns_answer recieved_answer {};
    get_answer(recieved_answer, recievedBuffer, offset);

    std::cout << "Answer section (1)" << std::endl;
    std::cout << recieved_answer.name << ", ";
    PrintQuestionType_Class(recieved_answer.dnstype, recieved_answer.dnsclass);
    std::cout << ", " << recieved_answer.ttl << ", ";
    PrintRecievedAddress(recievedBuffer, offset, recieved_answer.datalength, recieved_answer.dnstype);

    //printCharArrayAsHex(recievedBuffer + offset, bytes_received - offset);

    std::cout << "Authority section (0)" << std::endl;
    std::cout << "Additional section (0)" << std::endl;

    //printCharArrayAsHex(recievedBuffer + offset, bytes_received - offset);
    if (DEBUG) {
        std::cout << "* A pohádky byl konec :) *\n";
    }
    exit(EXIT_SUCCESS);
}