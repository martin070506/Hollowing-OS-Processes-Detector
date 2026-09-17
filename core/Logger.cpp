#include "Logger.h"
#include "Constants.h"
Logger::Logger(){
    
}
Logger* Logger::instance = nullptr;

Logger* Logger::getInstance() {
    if (instance == nullptr) {
        instance = new Logger();
    }
    return instance;
}

void Logger::log(Level log_lvl, std::string log_msg) const {
    if(log_lvl <  Constants::threshold){
        return;
    }
    else{
        std::cout << "[" << getLogString(log_lvl) << "] " << log_msg << std::endl;
    }
    
}



std::string Logger::getLogString(Level log_level) const {
    switch (log_level) {
        case Level::TRACE:
            return "TRACE";
        case Level::DEBUG:
            return "DEBUG";
        case Level::INFO:
            return "INFO";
        case Level::WARNING:
            return "WARNING";
        case Level::FAILED:
            return "FAILED";
        default:
            return "UNKNOWN";
    }
}