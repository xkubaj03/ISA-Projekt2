/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */

#include<sys/socket.h>
#include<unistd.h>  //close

#include<arpa/inet.h>   //inet_addr
#include<netinet/in.h>  //sockaddr_in
#include <vector>

#include "../include/DNSHeader.hpp"
#include "../include/DNSQuestion.hpp"
#include "../include/DNSAnswer.hpp"

#define BUFFER 1024

#define DEBUG 1

int main(int argc, char **argv) {
    Helper helper;
    Parameters param(argc, argv);

    char dns_packet[BUFFER];
    int offset = 0;

    Header header(param);
    Question question(param);

    header.ParseHeaderInBuffer(dns_packet, offset);
    question.ParseQuestionInBuffer(dns_packet, offset);

    int sock;
    if ((sock = socket(AF_INET, SOCK_DGRAM, 0)) == -1) {
        std::cerr << "socket() failed\n";
        exit(1);
    }

    struct sockaddr_in server;
    server.sin_addr.s_addr = inet_addr(helper.getIP(param.getSParam()).c_str());
    server.sin_family = AF_INET;
    server.sin_port = htons(param.getPParam());

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

    Header recieved_header(recievedBuffer, offset);
    helper.printHeaderInfo(recieved_header.getFlags());

    Question recieved_question(recievedBuffer, offset);
    recieved_question.PrintQuestion();

    std::vector<int> counts = {
            recieved_header.getAnCount(),
            recieved_header.getNsCount(),
            recieved_header.getArCount()
    };

    std::vector<std::vector<Answer>> AnsAuthAdd;
    for (int i = 0; i < 3; ++i) {
        std::vector<Answer> row;
        helper.PrintAns(i, counts[i]);
        for (int j = 0; j < counts[i]; ++j) {
            row.push_back(Answer(recievedBuffer, offset));
            row[j].PrintAnswer();
        }
        AnsAuthAdd.push_back(row);
    }

    helper.printCharArrayAsHex(recievedBuffer + offset, bytes_received - offset);


    if (DEBUG) {
        std::cout << "* A pohádky byl konec :) *\n";
    }
    exit(EXIT_SUCCESS);
}