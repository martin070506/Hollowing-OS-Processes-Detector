#pragma once
#include "../Const/ProcessInfo.h"
#include <vector>
#include <optional>
#include "windows.h"
class ProcessEnumerator{
    private:
        std::optional<std::wstring> resolvePath(DWORD pid);
        bool shouldSkip(const ProcessInfo& info);
    public:
        std::vector<ProcessInfo> enumerate();
};