#pragma once
#include <windows.h>
#include <string>
#include <vector>
#include <optional>
#include <cstdint>

class DiskImage {
private:
    IMAGE_DOS_HEADER DOS_Header;
    IMAGE_NT_HEADERS64 NT_Headers;
    std::vector<IMAGE_SECTION_HEADER> SectionHeaders;
    bool validSignature;
    bool loaded;                         // did we open+map+parse at all?

    bool parse(const std::byte* viewBase, size_t fileSize);

public:
    explicit DiskImage(const std::wstring& path);

    bool isLoaded()            const { return loaded; }
    bool signaturesValid()     const { return validSignature; }
    DWORD entryPointRva()      const { return NT_Headers.OptionalHeader.AddressOfEntryPoint; }
    ULONGLONG preferredImageBase() const { return NT_Headers.OptionalHeader.ImageBase; }
    DWORD sizeOfImage()        const { return NT_Headers.OptionalHeader.SizeOfImage; }
    const std::vector<IMAGE_SECTION_HEADER>& sections() const { return SectionHeaders; }

    std::optional<DWORD> rvaToFileOffset(DWORD rva) const;
};