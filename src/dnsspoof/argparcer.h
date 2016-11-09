//
// Created by bensoer on 18/10/16.
//

#ifndef INC_8505_A3_BACKDOOR_ARGPARCER_H
#define INC_8505_A3_BACKDOOR_ARGPARCER_H

#include <string>

#include <cstdlib>
#include <iostream>
#include <sstream>


using namespace std;

/**
* ArgParser makes retrieving commandline arguments easy. Pass the appropriate method the tag before the item you would
* like to retrieve from the command line args, and pass the argv array along with argc.
*/
class ArgParcer{

public:
    //finds param passed tag then gets associated value and returns it as a string
    //returns "-1" on failure to find tag
    string GetTagData(string preTag, char *argArray[], int length)
    {
        for(int i = 1; i < length; ++i)
        {
            if(preTag.compare(argArray[i])==0)
            {
                int t = i +1;
                return argArray[t];
            }
        }
        return "-1";

    }

    bool TagExists(string preTag, char *argArray[], int length)
    {
        for(int i = 1; i < length; ++i)
        {
            if(preTag.compare(argArray[i])==0)
            {
                return true;
            }
        }
        return false;

    }

    //finds param passed tag then gets associated value and returns it as an int
    //returns -1 on failure to find tag
    int GetTagVal(string preTag, char *argArray[], int length)
    {
        for(int i = 1; i < length; ++i)
        {
            if(preTag.compare(argArray[i])==0)
            {
                int t = i+1;

                string number = (argArray[t]);

                int num;

                istringstream( number) >> num;

                return num;
            }

        }
        return -1;

    }

private:

};





#endif //INC_8505_A3_BACKDOOR_ARGPARCER_H
