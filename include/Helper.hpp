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
    static void printUsage() {
        std::cerr << "Usage: ./dns -s server [-r] [-x] [-6] [-p port] name" << std::endl;
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

    std::string reverseIPv4Address(std::string address) {
        sockaddr_storage addr;
        address = getSIP(address, addr);
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

    std::string expandAndReverseIPv6Address(std::string address) {
        struct in6_addr addr;
        if (inet_pton(AF_INET6, address.c_str(), &addr) != 1) {
            return "Invalid IPv6 address";
        }

        std::stringstream expanded;
        expanded << std::hex << std::setfill('0');
        for (int i = 0; i < 8; ++i) {
            expanded << std::setw(4) << ntohs(addr.s6_addr16[i]);
            if (i < 7) {
                expanded << ":";
            }
        }

        return expanded.str().append(".ip6.arpa.");
    }

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

    std::string encodeIPv6(std::string input) {
        std::string ret;

        for(uint i = 0; i < 39; i++) {
            if(input[i] != ':') {
                ret += '\001';
                ret += input[i];
            }
        }
        ret += "\003ip6\004arpa\000";

        return ret;

    }

    std::string encodeDN_IPv4_Ipv6(std:: string input) {
        if(input.length() == 49) {
            return encodeIPv6(input);
        }

        return encodeDN_IPv4(input);
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
};

#endif //Helper_HPP