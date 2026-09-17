#pragma once
#include <iostream>
#include "Level.h"
class Logger{
    private:
        Logger();
        static Logger* instance;
    public:
        static Logger* getInstance();
        void log(Level log_lvl, std::string log_msg) const;
        std::string getLogString(Level log_level) const;
        Logger(Logger& other)=delete;
        Logger& operator=(const Logger other)=delete;
};

