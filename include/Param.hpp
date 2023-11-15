/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#ifndef Param_HPP
#define Param_HPP

#include <getopt.h>
#include <iostream>
#include "LittleHelpers.hpp"

class Parameters {
private:
    bool r_param = false;
    bool x_param = false;
    bool a6_param = false;
    uint p_param = 53;
    std::string s_param;
    std::string address_param;

public:
    Parameters(int argc, char *argv[]) {
        Helper helper;
        int opt;

        while ((opt = getopt(argc, argv, "rx6s:p:")) != -1) {
            switch (opt) {
                case 'r':
                    this->setRParam(true);
                    break;

                case 'x':
                    this->setXParam(true);
                    break;

                case '6':
                    this->setA6Param(true);
                    break;

                case 's':
                    this->setSParam(optarg);
                    break;

                case 'p':
                    if (std::stoi(optarg) < 0 || std::stoi(optarg) > 65535) {
                        std::cout << "Wrong port number! (0 - 65535)\n";
                        exit(0);
                    }

                    this->setPParam(std::stoi(optarg));
                    break;

                default:
                    std::cerr << "Unknown parameter: " << static_cast<char>(optopt) << std::endl;
                    helper.printUsage();
                    exit(0);
            }
        }

        if (optind < argc) {
            this->setAddressParam(argv[optind]);

        } else {
            std::cerr << "Missing targeted address!" << std::endl;
            helper.printUsage();
            exit(0);
        }

        if (this->getSParam().empty()) {
            std::cerr << "Requiered parameter -s with argument" << std::endl;
            helper.printUsage();
            exit(0);
        }

        if (this->getA6Param() && this->getXParam()) {
            std::cerr << "Parameters -x and -6 can't be used together" << std::endl;
            helper.printUsage();
            exit(0);
        }
    }

    bool getRParam() const { return r_param; }

    bool getXParam() const { return x_param; }

    bool getA6Param() const { return a6_param; }

    uint getPParam() const { return p_param; }

    std::string getSParam() const { return s_param; }

    std::string getAddressParam() const { return address_param; }

private:
    void setRParam(bool value) { r_param = value; }

    void setXParam(bool value) { x_param = value; }

    void setA6Param(bool value) { a6_param = value; }

    void setPParam(uint value) { p_param = value; }

    void setSParam(const std::string &value) { s_param = value; }

    void setAddressParam(const std::string &value) { address_param = value; }
};

#endif //Param_HPP