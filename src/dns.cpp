/*
 *  VUT FIT ISA Projekt DNS Resolver
 *  Autor: Josef Kuba
 *  Login: xkubaj03
 */
#include <vector>

#include "../include/DNSHeader.hpp"
#include "../include/DNSQuestion.hpp"
#include "../include/DNSAnswer.hpp"
#include "../include/SocketDataManager.hpp"

#define DEBUG 1

int main(int argc, char **argv) {
    Helper helper;
    Parameters param(argc, argv);

    SocketDataManager dataManager(param);

    Header header(param);
    Question question(param);

    header.ParseHeaderInBuffer(dataManager.sendBuffer, dataManager.sendOffset);
    question.ParseQuestionInBuffer(dataManager.sendBuffer, dataManager.sendOffset);

    dataManager.Send();
    dataManager.Recieve();


    Header recieved_header(dataManager.recvBuffer, dataManager.recvOffset);
    helper.printHeaderInfo(recieved_header.getFlags());

    Question recieved_question(dataManager.recvBuffer, dataManager.recvOffset);
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
            row.push_back(Answer(dataManager.recvBuffer, dataManager.recvOffset));
            row[j].PrintAnswer();
        }
        AnsAuthAdd.push_back(row);
    }

    helper.printCharArrayAsHex(dataManager.recvBuffer + dataManager.recvOffset,
                               dataManager.getBytesReceived() - dataManager.recvOffset);


    std::cout << "* A pohádky byl konec :) *\n";

    exit(EXIT_SUCCESS);
}