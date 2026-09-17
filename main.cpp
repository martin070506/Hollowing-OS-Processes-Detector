#include <iostream>
#include "./core/Logger.h"
#include "./Const/ProcessInfo.h"


int main() {
    std::cout << "Hello, World!!!!" << std::endl;
    ProcessInfo p =ProcessInfo(ProcessInfo(0,0,"MMM","NNN"));
    std::cout<<p.getExecutableName()<<std::endl;

    return 0;
}
