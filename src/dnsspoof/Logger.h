//
// Created by bensoer on 25/10/16.
//

#ifndef INC_8505_A4_DNSSPOOF_LOGGER_H
#define INC_8505_A4_DNSSPOOF_LOGGER_H

#include<string>

using namespace std;

class Logger {

private:
    static bool isDebug;

public:

    static void setDebug(bool state);

    static void print(string message);
    static void println(string message);

    static void error(string message);
    static void debug(string message);
};


#endif //INC_8505_A4_DNSSPOOF_LOGGER_H
