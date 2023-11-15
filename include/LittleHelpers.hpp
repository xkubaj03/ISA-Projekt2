/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef LittleHelpers_HPP
#define LittleHelpers_HPP

#include <iomanip>      //printStringAsHex
#include<netdb.h>       //Gethostbyname
#include<arpa/inet.h>   //inet_ntop
#include <iostream>
#include <string.h>     //string

class Helper {
public:
    static void printUsage() {
        std::cout << "Usage: ./dns -s server [-r] [-x] [-6] [-p port] name" << std::endl;
    }

    static void printCharArrayAsHex(const char *array, std::size_t length) {
        for (std::size_t i = 0; i < length; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<unsigned char>(array[i])) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    static void printStringAsHex(const std::string &str) {
        for (char c: str) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<unsigned char>(c))
                      << " ";
        }
        std::cout << std::dec << std::endl;
    }

    std::string get_DN(char *buffer, int &offset) {
        std::string ret;
        uint16_t pointer;
        uint8_t label_length;

        while (true) {
            memcpy(&pointer, buffer + offset, sizeof(uint16_t));
            pointer = ntohs(pointer);
            if (pointer >> 14 == 3) {
                int tmp = offset;
                offset = (pointer & 0x3FFF);

                std::string tmp_string = get_DN(buffer, offset);
                if (!ret.empty()) {
                    tmp_string[0] = '.';
                }
                ret += tmp_string;

                offset = tmp + 2;
                return ret;
            }
            label_length = buffer[offset];

            // \0 Ends the name
            if (label_length == 0) {
                offset++; // Skip null lable
                return ret;
            }

            // If there was previous domain we add dot
            if (!ret.empty()) {
                ret += '.';
            }

            // We add label to the domain
            for (int i = 1; i <= label_length; i++) {
                ret += buffer[offset + i];
            }

            offset += label_length + 1; // Skip label and label length
        }
    }

    std::string get_IPv4(std::string name) {
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

    std::string get_IP(const std::string &name, int family = AF_UNSPEC) {
        struct addrinfo hints, *result, *rp;
        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = family;

        int ret = getaddrinfo(name.c_str(), nullptr, &hints, &result);
        if (ret != 0) {
            std::cerr << "getaddrinfo error: " << gai_strerror(ret) << std::endl;
            exit(1);
        }

        for (rp = result; rp != nullptr; rp = rp->ai_next) {
            if (rp->ai_family == AF_INET) { // IPv4
                struct sockaddr_in *ipv4 = (struct sockaddr_in *)rp->ai_addr;
                char ip[INET_ADDRSTRLEN];
                inet_ntop(AF_INET, &(ipv4->sin_addr), ip, INET_ADDRSTRLEN);
                freeaddrinfo(result);
                return ip;
            } else if (rp->ai_family == AF_INET6) { // IPv6
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)rp->ai_addr;
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip, INET6_ADDRSTRLEN);
                freeaddrinfo(result);
                return ip;
            }
        }

        freeaddrinfo(result);
        std::cerr << "No valid IP address found for the given hostname." << std::endl;
        exit(1);
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

    std::string reverseDN(std::string hostname) {
        hostname = get_IPv4(hostname);
        std::string ret;

        int pos;
        for (int i = 0; i < 3; i++) {
            pos = hostname.rfind('.');
            ret.append(hostname, pos + 1);
            ret.append(".");
            hostname = hostname.substr(0, pos);
        }
        ret.append(hostname);
        ret.append(".in-addr.arpa.");
        return ret;
    }

    void printHeaderInfo(uint16_t flags) {
        std::cout << "Authoritative: ";
        if (flags & (1 << 10)) {
            std::cout << "Yes";
        } else {
            std::cout << "No";
        }
        std::cout << ", Recursive: ";
        if (flags & (1 << 8)) {
            std::cout << "Yes";
        } else {
            std::cout << "No";
        }
        std::cout << ", Truncated: ";
        if (flags & (1 << 9)) {
            std::cout << "Yes" << std::endl;
        } else {
            std::cout << "No" << std::endl;
        }
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

    void PrintAns(int index, uint16_t x) {
        switch (index) {
            case 0:
                std::cout << "Answer section (" << x << ")" << std::endl;
                break;
            case 1:
                std::cout << "Authority section (" << x << ")" << std::endl;
                break;
            case 2:
                std::cout << "Additional section (" << x << ")" << std::endl;
                break;
            default:
                std::cout << "PrintAns index out of bounds (" << x << ")" << std::endl;
                break;
        }
    }
};

#endif //LittleHelpers_HPP