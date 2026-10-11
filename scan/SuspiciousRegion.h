#pragma once
#include <windows.h>
#include <cstdint>

struct SuspiciousRegion {
    void*   baseAddress;     // where the region starts
    size_t  regionSize;      // how big it is
    DWORD   protection;      // the raw protection flags (PAGE_EXECUTE_READWRITE, etc.)
    DWORD   state;           // committed / reserved / free
    bool    isPrivate;       // true = private memory, false = image-backed (from a file)
};