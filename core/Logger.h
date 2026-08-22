#pragma once
#include <iostream>
#include "Level.h"
class Logger{
    private:

    public:
        Logger();
        void log(Level log_lvl, std::string log_msg) const;
        std::string getLogString(Level log_level) const;
};