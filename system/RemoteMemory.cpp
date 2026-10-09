#include "RemoteMemory.h"
RemoteMemory::RemoteMemory(HANDLE _h):currentHandle(_h){}

//this method takes [size] bytws from the remote adress and copies to buffer
bool RemoteMemory::read(const void* remoteAddress,void* buffer, size_t size)
{
    SIZE_T bytesRead=0;
    bool success=ReadProcessMemory(currentHandle,remoteAddress,buffer,size,&bytesRead);
    if(!success)
    {
        return false;
    } 
    return (bytesRead==size);
}

template <typename T>
std::optional<T> RemoteMemory::typeRead(const void* remoteAddress)
{
    T destination{};
    bool successRead=read(remoteAddress, &destination, sizeof(destination));
    if(!successRead)
    {
        return std::nullopt;
    } 
    return destination;
}

std::optional<std::vector<std::byte>> RemoteMemory::readBuffer(const void* remoteAddress, size_t size)
{
    std::vector<std::byte> arr(size);
    bool sucessRead=read(remoteAddress,arr.data(),size);
    if(!sucessRead) 
        return std::nullopt;
    return arr;
}