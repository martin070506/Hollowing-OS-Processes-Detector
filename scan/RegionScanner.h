#pragma once
#include <windows.h>
#include <vector>
#include "SuspiciousRegion.h"

class RegionScanner {
public:
    explicit RegionScanner(HANDLE processHandle);   // borrowed handle

    std::vector<SuspiciousRegion> scan();

private:
    HANDLE _processHandle;   // raw, non-owning — borrowed, like RemoteMemory

    static bool isWritableExecutable(DWORD protection);
};