#pragma once
#include <string>
class PrivilegeManager {
    private:
        static bool setPrivilege(const std::wstring& privilegeName, bool enable); // Prevent instantiation of this class

    public:
        static bool turnOnPrivilege(const std::wstring& privilegeName);
        static bool isProcessElevated();
        static bool turnOffPrivilege(const std::wstring& privilegeName);
        PrivilegeManager() = default; // Prevent instantiation of this class

};
