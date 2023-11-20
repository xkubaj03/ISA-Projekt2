/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#include "../include/Helper.hpp"

#include <iostream>
#include <gtest/gtest.h>

TEST(HelperTest, getSIP) {
    Helper helper;
    sockaddr_storage addr;
    std::string ip = helper.getSIP("www.fit.vutbr.cz", addr);
    EXPECT_EQ("2001:67c:1220:809::93e5:917", ip);
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
