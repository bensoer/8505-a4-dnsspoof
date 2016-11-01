//
// Created by bensoer on 25/10/16.
//

#include <iostream>
#include "Logger.h"

/**
 * statuc variable that enables and disables debug logging
 */
bool Logger::isDebug = false;

/**
 * debug writes the passed in message to console using Logger::println as long as debug mode is enabled
 * @param message String - the message to be printed
 */
void Logger::debug(string message) {
    if(Logger::isDebug){
        Logger::println(message);
    }
}

/**
 * println is a helper method that prints the passed in message to stdout and appends a return character at the end
 * @param message String - the message to be printed
 */
void Logger::println(string message) {
    cout << message << endl;
}

/**
 * print is a helper method that prints the passed in message to stdout
 * @param message String - the message to be printed
 */
void Logger::print(string message) {
    cout << message;
}

/**
 * error is a helper method that prints the passed in message to stderr
 * @param message String - the message to be printed
 */
void Logger::error(string message) {
    cerr << message << endl;
}

/**
 * setDebug is a helper method that sets the state for the logger as to whether it is in debug mode or not
 * @param state Boolean - state as to whether the Logger can print debug messages or not. True = debug messages are printed
 */
void Logger::setDebug(bool state) {
    Logger::isDebug = state;
}