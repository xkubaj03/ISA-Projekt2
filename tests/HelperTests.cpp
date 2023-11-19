/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#include "../include/Helper.hpp"

#include <iostream>
#include <gtest/gtest.h>
#include <cstdlib> //system()

TEST(ReverseIPTest, IPv4) {
    Helper helper;
    std::string reversedIP = helper.ReverseIP("147.229.9.26");
    EXPECT_EQ("26.9.229.147.in-addr.arpa.", reversedIP);
}

TEST(ReverseIPTest, IPv6) {
    Helper helper;
    std::string reversedIP = helper.ReverseIP("2001:67c:1220:808::93e5:80c");
    EXPECT_EQ("2001:067c:1220:0808:0000:0000:93e5:080c.ip6.arpa.", reversedIP);
}

TEST(EncodeIPTest, IPv4) {
    Helper helper;
    std::string encodedIP = helper.encodeDN_IPv4_Ipv6("147.229.9.26.in-addr.arpa.");
    EXPECT_EQ("\003147\003229\0019\00226\007in-addr\004arpa", encodedIP.substr(0, encodedIP.length() - 1));
}

TEST(FunctionalTest, dns) {
    const char* command = "./dns";

    FILE* pipe = popen(command, "r");
    if (!pipe) {
        std::cerr << "pipe error" << std::endl;
        exit(1);
    }

    char buffer[128];
    std::string output = "";

    while (fgets(buffer, sizeof(buffer), pipe) != NULL) {
        output += buffer;
    }

    pclose(pipe);

    if (output.empty()) {
        std::cout << "Program nemá žádný výstup." << std::endl;
    } else {
        std::cout << "Výstup programu:\n" << output << std::endl;
    }


}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
