#pragma once
#include <iostream>
class ProcessInfo {
    private:
        int processId_;
        int parentProcessId_;
        std::string executableName_;
        std::string path_;

    public:
        ProcessInfo(int processId, int parentProcessId,   const std::string& executableName,  const std::string& path);
        ProcessInfo(const ProcessInfo& other)=delete;
        ProcessInfo(ProcessInfo&& other):processId_(other.processId_),parentProcessId_(other.parentProcessId_),executableName_(std::move(other.executableName_)),path_(std::move(other.path_)){};
        int getProcessId() ;
        int getParentProcessId()  ;
        const std::string& getExecutableName();
        const std::string& getPath() ;


};