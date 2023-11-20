/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef Helper_HPP
#define Helper_HPP

#include <iomanip>      //printStringAsHex
#include<netdb.h>       //Gethostbyname
#include<arpa/inet.h>   //inet_ntop
#include <iostream>
#include <string.h>     //string
#include <sstream>

class Helper {
    // Class for some helper functions used by other classes and prints
public:
    static void printCharArrayAsHex(const char *array, std::size_t length) {
        // This method was created by Chat GPT 3.5
        for (std::size_t i = 0; i < length; ++i) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<unsigned char>(array[i])) << " ";
        }
        std::cout << std::dec << std::endl;
    }

    static void printStringAsHex(const std::string &str) {
        // This method was created by Chat GPT 3.5
        for (char c: str) {
            std::cout << std::hex << std::setw(2) << std::setfill('0')
                      << static_cast<int>(static_cast<unsigned char>(c))
                      << " ";
        }
        std::cout << std::dec << std::endl;
    }

    std::string get_DN(char *buffer, int &offset) {
        // This method was created by Chat GPT 3.5
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

    std::string getSIP(const std::string &input, sockaddr_storage &addr) {
        if (getAddressInfo(input, addr)) {
            if (addr.ss_family == AF_INET) {
                struct sockaddr_in *ipv4 = (struct sockaddr_in *) &addr;
                return inet_ntoa(ipv4->sin_addr);
            } else if (addr.ss_family == AF_INET6) {
                struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *) &addr;
                char ip[INET6_ADDRSTRLEN];
                inet_ntop(AF_INET6, &(ipv6->sin6_addr), ip, INET6_ADDRSTRLEN);
                return ip;
            }
            std::cerr << "Unsupported address family" << std::endl;
            exit(1);

        }
        std::cerr << "Failed to resolve address" << std::endl;
        exit(1);
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

    bool getAddressInfo(const std::string &input, struct sockaddr_storage &addr) {
        struct addrinfo hints, *res;
        memset(&hints, 0, sizeof hints);

        hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_DGRAM;

        int status = getaddrinfo(input.c_str(), NULL, &hints, &res);
        if (status != 0) {
            std::cerr << "getaddrinfo error: " << gai_strerror(status) << std::endl;
            return false;
        }

        memcpy(&addr, res->ai_addr, res->ai_addrlen);
        freeaddrinfo(res);
        return true;
    }
};

#endif //Helper_HPP