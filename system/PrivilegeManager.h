#pragma once
#include <string>
class PrivilegeManager {
    private:


    public:
        static bool turnOnPrivilege(const std::wstring& privilegeName);
        static bool isProcessElevated();

};
