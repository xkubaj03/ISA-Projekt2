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

struct Param {
    bool r_param = false;
    bool x_param = false;
    bool a6_param = false;
    std::string s_param = "";
    uint p_param = 53;
    std::string address_param = "";
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
    //std::string name;
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

#define IP_ADDR "127.0.0.1"      // a fixed server IP address
#define BUFFER 1024              // buffer length

#define DEBUG 1

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
                ret->p_param = std::stoi(optarg);
                break;
            default:
                std::cerr << "Unknown parameter: " << static_cast<char>(optopt) << std::endl
                          << "Usage: dns [-r] [-x] [-6] -s server [-p port] address" << std::endl;
                exit(1);
        }
    }

    if (optind < argc) {
        ret->address_param = argv[optind];
    } else {
        std::cerr << "Missing targeted address!" << std::endl
                  << "Usage: dns [-r] [-x] [-6] -s server [-p port] address" << std::endl;
        exit(1);
    }
    if (ret->s_param.empty()) {
        std::cerr << "Requiered parameter -s with argument" << std::endl
                  << "Usage: dns [-r] [-x] [-6] -s server [-p port] address" << std::endl;
        exit(1);
    }
}
// Funkce pro zakódování názvu domény do formátu DNS

void encodeDNSName(const std::string &hostname, std::array<uint8_t, 255> &dns_name) {
    dns_name.fill(0); // Inicializace pole nulami
    size_t offset = 0; // Aktuální pozice v poli

    for (size_t i = 0; i < hostname.length(); ++i) {
        if (hostname[i] == '.') {
            // Uložte délku aktuálního labelu
            dns_name[offset] = i - offset;
            ++offset;
            size_t labelStart = offset;

            // Zkopírujte znaky labelu
            for (size_t j = 0; j < i - offset; ++j) {
                dns_name[offset] = static_cast<uint8_t>(hostname[labelStart + j]);
                ++offset;
            }
        }
    }

    // Nastavte nulový label na konec
    dns_name[offset] = 0;
}

int main(int argc, char **argv) {
    Param parameters;
    read_args(argc, argv, &parameters);
    if (DEBUG) {
        std::cout << "Rekurze: " << parameters.r_param << std::endl;
        std::cout << "Reverzní dotaz: " << parameters.x_param << std::endl;
        std::cout << "Použít AAAA: " << parameters.a6_param << std::endl;
        std::cout << "Server: " << parameters.s_param << std::endl;
        std::cout << "Port: " << parameters.p_param << std::endl;
        std::cout << "Adresa: " << parameters.address_param << std::endl;
    }
    /*Authoritative: No, Recursive: Yes, Truncated: No
    Question section (1)
    www.fit.vut.cz., A, IN
    Answer section (1)
    www.fit.vut.cz., A, IN, 14400, 147.229.9.26
    Authority section (0)
    Additional section (0)*/

    /*
    std::cout <<
    "Authoritative: "   << xxx << ", " <<
    "Recursive: "       << yyy << ", " <<
    "Truncated: "       << ccc;*/


    dns_header header;
    header.id = htons(0x1234);
    header.flags = htons(0x0100);
    header.qdcount = htons(1);
    header.ancount = htons(0);
    header.nscount = htons(0);
    header.arcount = htons(0);

    dns_question question;
    question.dnstype = htons(1);  /* QTYPE 1=A */
    question.dnsclass = htons(1); /* QCLASS 1=IN */

    /*dns_answer answer;
    dns_authority authority;
    dns_additional additional;*/


    // Sestavení DNS packetu
    char dns_packet[1024];
    int offset = 0;

    // Kopírování hlavičky do bufferu
    memcpy(&dns_packet[offset], &header, sizeof(dns_header));
    offset += sizeof(dns_header);


    //memcpy(&dns_packet[offset], &question, sizeof(question));
    //offset += sizeof(question);
    char x[] = " www github com ";
    x[0] = 3;
    x[4] = 6;
    x[11] = 3;
    x[15] = 0;

    memcpy(&dns_packet[offset], &x, sizeof(x));
    offset += sizeof(x)-1; //null byte of string
    memcpy(&dns_packet[offset], &question, sizeof(question));
    offset += sizeof(question);
    /*memcpy(&dns_packet[offset], &answer, sizeof(answer));
    offset += sizeof(answer);

    memcpy(&dns_packet[offset], &additional, sizeof(additional));
    offset += sizeof(additional);

    memcpy(&dns_packet[offset], &authority, sizeof(authority));
    offset += sizeof(authority);*/


    /* std::array<uint8_t, 255> dns_name{};
  //std::array<uint8_t> dns_name;
  encodeDNSName(question.name, dns_name);*/

    int sock;
    struct sockaddr_in server;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1)   //create a client socket
        err(1, "socket() failed\n");

    printf("* Socket created\n");
    server.sin_addr.s_addr = inet_addr(IP_ADDR);   // set the server address
    server.sin_family = AF_INET;
    server.sin_port = htons(parameters.p_param);                 // set the server port (network byte order)
    // Odeslání DNS packetu na server
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
