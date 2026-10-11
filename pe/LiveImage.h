#pragma once
#include <cstddef>
#include <windows.h>
#include <vector>
#include "../system/RemoteMemory.h"

class LiveImage
{
private:
    RemoteMemory _rm;
    HANDLE _processHandle;
    const std::byte* BaseAddress;
    IMAGE_DOS_HEADER DOS_Header;
    IMAGE_NT_HEADERS64 NT_Headers;
    std::vector<IMAGE_SECTION_HEADER> SectionHeaders;
    bool validSignature;
    bool loaded;                         // <-- NEW

    std::byte* findBaseAddress();

public:
    LiveImage(HANDLE h);

    // --- getters the DetectionEngine needs ---
    bool isLoaded()        const { return loaded; }
    bool signaturesValid() const { return validSignature; }
    WORD dosMagic()        const { return DOS_Header.e_magic; }
    DWORD ntSignature()    const { return NT_Headers.Signature; }
    DWORD entryPointRva()  const { return NT_Headers.OptionalHeader.AddressOfEntryPoint; }
    DWORD sizeOfImage()    const { return NT_Headers.OptionalHeader.SizeOfImage; }
    const std::byte* baseAddress() const { return BaseAddress; }
    const std::vector<IMAGE_SECTION_HEADER>& sections() const { return SectionHeaders; }
};