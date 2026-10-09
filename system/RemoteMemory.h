#pragma once
#include "ScopedHandle.h"
#include <windows.h>
#include <string>
#include <optional>
#include <vector>

class RemoteMemory
{
    private:
        // the handle must live after this object so we use a regular HANDLE
        HANDLE currentHandle;
    public:
        bool read(const void* remoteAddress,void* buffer, size_t size);

        template <typename T>
        std::optional<T> typeRead(const void* remoteAdress);

        std::optional<std::vector<std::byte>> readBuffer(const void* remoteAddress, size_t size);
        RemoteMemory(HANDLE _h);
        
};


