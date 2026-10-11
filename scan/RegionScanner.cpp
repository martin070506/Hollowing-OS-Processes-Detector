#include "RegionScanner.h"

RegionScanner::RegionScanner(HANDLE processHandle)
    : _processHandle(processHandle) {}

bool RegionScanner::isWritableExecutable(DWORD protection)
{
    // Strip modifier bits (PAGE_GUARD, PAGE_NOCACHE, etc.) before comparing.
    DWORD base = protection & 0xFF;
    return base == PAGE_EXECUTE_READWRITE ||
           base == PAGE_EXECUTE_WRITECOPY;
}

std::vector<SuspiciousRegion> RegionScanner::scan()
{
    std::vector<SuspiciousRegion> found;

    const std::byte* address = nullptr;   // start at the bottom of the address space
    MEMORY_BASIC_INFORMATION mbi{};

    while (VirtualQueryEx(_processHandle, address, &mbi, sizeof(mbi)) == sizeof(mbi)) {
        // Only committed memory matters — reserved/free regions hold nothing.
        if (mbi.State == MEM_COMMIT && isWritableExecutable(mbi.Protect)) {
            SuspiciousRegion region{};
            region.baseAddress = mbi.BaseAddress;
            region.regionSize  = mbi.RegionSize;
            region.protection  = mbi.Protect;
            region.state       = mbi.State;
            region.isPrivate   = (mbi.Type == MEM_PRIVATE);   // vs MEM_IMAGE / MEM_MAPPED
            found.push_back(region);
        }

        // Advance to the next region: current base + current size.
        const std::byte* next =
            reinterpret_cast<const std::byte*>(mbi.BaseAddress) + mbi.RegionSize;

        // Overflow guard: near the top of memory, base+size can wrap around.
        if (next <= address)
            break;
        address = next;
    }

    return found;
}