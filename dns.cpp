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
    if (DEBUG) {
        std::cout << "Encoded: ";
        printStringAsHex(hostname);
        std::cout << std::endl;
    }

    return hostname;
}

in_addr_t getIP(std::string name) {
    struct hostent *host_info;

    host_info = gethostbyname(name.c_str());
    if (host_info == NULL) {
        std::cerr << "gethostbyname error" << std::endl;
        exit(1);
    }

    struct in_addr *ipv4_addr = (struct in_addr *) host_info->h_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipv4_addr, ip, INET_ADDRSTRLEN);

    if (DEBUG)
        std::cout << "IPv4 Address: " << ip << std::endl;

    return inet_addr(ip);
}

std::string encodeReverse(std::string hostname) {
    struct hostent *host_info;

    host_info = gethostbyname(hostname.c_str());
    if (host_info == NULL) {
        std::cerr << "gethostbyname error" << std::endl;
        exit(1);
    }

    struct in_addr *ipv4_addr = (struct in_addr *) host_info->h_addr;
    char ip[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, ipv4_addr, ip, INET_ADDRSTRLEN);

    hostname = ip;
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

int main(int argc, char **argv) {
    Param parameters;
    read_args(argc, argv, &parameters);
    if (0) {
        std::cout << "Rekurze: " << parameters.r_param << std::endl;
        std::cout << "Reverzní dotaz: " << parameters.x_param << std::endl;
        std::cout << "Použít AAAA: " << parameters.a6_param << std::endl;
        std::cout << "Server: " << parameters.s_param << std::endl;
        std::cout << "Port: " << parameters.p_param << std::endl;
        std::cout << "Adresa: " << parameters.address_param << std::endl;
    }

    char dns_packet[BUFFER];
    int offset = 0;

    dns_header header{};
    header.id = htons(0x1234);

    int16_t flags = 0x0000;
    if (parameters.r_param)
        flags |= (1 << 8);
    if (parameters.x_param)
        flags |= (1 << 7);
    header.flags = htons(flags);
    header.qdcount = htons(1);
    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);

    memcpy(&dns_packet[offset], &header, sizeof(dns_header));
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

    memcpy(&dns_packet[offset], question.name.c_str(), question.name.length() + 1);
    offset += question.name.length() + 1;
    memcpy(&dns_packet[offset], &question.dnstype, sizeof(question.dnstype));
    offset += sizeof(question.dnstype);
    memcpy(&dns_packet[offset], &question.dnsclass, sizeof(question.dnsclass));
    offset += sizeof(question.dnsclass);

    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        std::cerr << "socket() failed\n";
        exit(1);
    }

    if (DEBUG) {
        std::cout << "* Socket created\n";
    }


    struct sockaddr_in server;
    server.sin_addr.s_addr = getIP(parameters.s_param);
    server.sin_family = AF_INET;
    server.sin_port = htons(parameters.p_param);

    ssize_t sent_bytes = sendto(sock, dns_packet, offset, 0, (struct sockaddr *) &server, sizeof(server));
    if (sent_bytes < 0) {
        std::cout << "Chyba při odesílání DNS packetu" << std::endl;
        exit(1);
    }


    close(sock);
    if (DEBUG)
        std::cout << "* Closing the client socket ...\n";
    exit(EXIT_SUCCESS);
}