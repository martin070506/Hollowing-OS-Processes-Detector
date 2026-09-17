#include "ProcessInfo.h"

ProcessInfo::ProcessInfo(int processId, int parentProcessId,  const std::string& executableName,  const std::string& path)
    : processId_(processId), parentProcessId_(parentProcessId), executableName_(executableName), path_(path) {}

int ProcessInfo::getProcessId()  {
    return processId_;
}

int ProcessInfo::getParentProcessId() {
    return parentProcessId_;
}

 const std::string& ProcessInfo::getExecutableName()  {
    return executableName_;
}

 const std::string& ProcessInfo::getPath()  {
    return path_;
}