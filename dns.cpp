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

    if (0)
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

void PrintQuestionType(int16_t x) {
    switch (x) {
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

    if (0) {
        std::cout << "* Socket created\n";
    }


    struct sockaddr_in server;
    server.sin_addr.s_addr = getIP(parameters.s_param);
    server.sin_family = AF_INET;
    server.sin_port = htons(parameters.p_param);

    ssize_t sent_bytes = sendto(sock, dns_packet, offset, 0, (struct sockaddr *) &server, sizeof(server));
    if (sent_bytes < 0) {
        std::cerr << "Chyba při odesílání DNS packetu" << std::endl;
        exit(1);
    }
    //recieving
    char recievedBuffer[BUFFER];
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
    printCharArrayAsHex(recievedBuffer, bytes_received);

    // store recieved data into headers
    dns_header recieved_header {};
    memcpy(&recieved_header, recievedBuffer, sizeof(dns_header));
    recieved_header.id = ntohs(recieved_header.id);
    recieved_header.flags = ntohs(recieved_header.flags);
    recieved_header.qdcount = ntohs(recieved_header.qdcount);
    recieved_header.ancount = ntohs(recieved_header.ancount);
    recieved_header.nscount = ntohs(recieved_header.nscount);
    recieved_header.arcount = ntohs(recieved_header.arcount);

    //std::cout << "ID: 0x" << std::hex << recieved_header.id << std::endl << std::dec;

    std::cout << "Authoritative: ";
    if (recieved_header.flags & (1 << 10)) {
        std::cout << "Yes";
    } else {
        std::cout << "No";
    }
    std::cout << ", Recursive: ";
    if (recieved_header.flags & (1 << 8)) {
        std::cout << "Yes";
    } else {
        std::cout << "No";
    }
    std::cout << ", Truncated: ";
    if (recieved_header.flags & (1 << 9)) {
        std::cout << "Yes" << std::endl;
    } else {
        std::cout << "No" << std::endl;
    }

    char recieved_question_name[SBUFF];

    char *nullTerminator = strchr(recievedBuffer + sizeof(dns_header), '\0');
    int nullIndex = nullTerminator - recievedBuffer;

    memcpy(&recieved_question_name, recievedBuffer + sizeof(dns_header), nullIndex);
    recieved_question_name[nullIndex -  sizeof(dns_header)] = '\0';
    recieved_question_name[0] = ' ';
    //every char < 46 replace with dot
    for (int i = 1; (i < nullIndex) && (recieved_question_name[i] != '\0'); i++) {
        if (recieved_question_name[i] < 46) {
            recieved_question_name[i] = '.';
        }
    }
    std::cout << "Question section(1)" << std::endl;
    std::cout << recieved_question_name << ", ";

    uint16_t recieved_question_type;
    uint16_t recieved_question_class;

    memcpy(&recieved_question_type, recievedBuffer + nullIndex + 1, sizeof(uint16_t));
    memcpy(&recieved_question_class, recievedBuffer + nullIndex + 1 + sizeof(uint16_t), sizeof(uint16_t));

    recieved_question_type = ntohs(recieved_question_type);
    recieved_question_class = ntohs(recieved_question_class);

    PrintQuestionType(recieved_question_type);


    if (recieved_question_class == 1) {
        std::cout << ", IN" << std::endl;
    } else {
        std::cout << ", Unknown" << std::endl;
    }

    std::cout << "Answer section (1)" << std::endl;
    //check first byte if is it pointer
    if ((recievedBuffer[nullIndex + 1 + 2*sizeof(uint16_t)] & 0xc0) == 0xc0) {
        std::cout << "Pointer!!" << std::endl;


    }else {
        std::cout << "No Pointer!!! " << std::endl;

    }



    if (DEBUG)
        std::cout << "* Closing the client socket ...\n";
    exit(EXIT_SUCCESS);
}