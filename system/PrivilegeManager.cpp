#include "PrivilegeManager.h"
#include <windows.h>
#include "../core/Logger.h"
#include "../core/ScopedHandle.h"

bool PrivilegeManager::isProcessElevated()
{
    HANDLE tokenHandle=nullptr;
    TOKEN_ELEVATION elevation{};//also empty
    
    if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &tokenHandle)) {
        DWORD errorCode = GetLastError();
       
        Logger::getInstance()->log(Level::FAILED, "Failed to open process token. Error code: " + std::to_string(errorCode));
        return false;
    }
    ScopedHandle tokenScopedHandle(tokenHandle);
    
    if(!GetTokenInformation(tokenScopedHandle.GetHandle(), TokenElevation, &elevation, sizeof(elevation), nullptr)){
        DWORD errorCode = GetLastError();
       Logger::getInstance()->log(Level::FAILED, "Failed to get token information. Error code: " + std::to_string(errorCode));
        return false;
    }
    return elevation.TokenIsElevated != 0;
}

bool PrivilegeManager::turnOnPrivilege(const std::wstring& privilegeName, PrivilegeManager* selfPtr)
{
    return selfPtr->setPrivilege(privilegeName, true);
}

bool PrivilegeManager::turnOffPrivilege(const std::wstring& privilegeName, PrivilegeManager* selfPtr)
{
    return selfPtr->setPrivilege(privilegeName, false);
}



bool PrivilegeManager::setPrivilege(const std::wstring& privilegeName, bool enable)
{
    // 1. open your token WITH adjust access
    HANDLE tokenHandle = nullptr;
    if (!OpenProcessToken(GetCurrentProcess(),
                          TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                          &tokenHandle)) {
        DWORD e = GetLastError();
        Logger::getInstance()->log(Level::FAILED, "OpenProcessToken failed. Error: " + std::to_string(e));
        return false;
    }
    ScopedHandle token(tokenHandle);

    // 2. name -> LUID
    LUID luid{};
    if (!LookupPrivilegeValueW(nullptr, privilegeName.c_str(), &luid)) {
        DWORD e = GetLastError();
        Logger::getInstance()->log(Level::FAILED, "LookupPrivilegeValue failed. Error: " + std::to_string(e));
        return false;
    }

    // 3. build the privilege set
    TOKEN_PRIVILEGES tp{};
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = enable ? SE_PRIVILEGE_ENABLED : 0;

    // 4. apply
    if (!AdjustTokenPrivileges(token.GetHandle(), FALSE, &tp, sizeof(tp), nullptr, nullptr)) {
        DWORD e = GetLastError();
        Logger::getInstance()->log(Level::FAILED, "AdjustTokenPrivileges failed. Error: " + std::to_string(e));
        return false;
    }

    // 5. THE TRAP — it returns TRUE even when it granted nothing
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) {
        Logger::getInstance()->log(Level::FAILED, "Privilege not held by token (not assigned).");
        return false;
    }

    return true;
}