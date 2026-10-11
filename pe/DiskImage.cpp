#include "DiskImage.h"
#include <cstring>                    // memcpy
#include "../core/ScopedHandle.h"
#include "../core/Logger.h"

DiskImage::DiskImage(const std::wstring& path)
    : DOS_Header{}, NT_Headers{}, validSignature(false), loaded(false)
{
    // 1. Open the file — read access AND read sharing (it's executing!)
    ScopedHandle file( CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ,
                                   nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr) );
    if (!file.valid()) {
        Logger::getInstance()->log(Level::FAILED, "DiskImage: couldn't open file");
        return;
    }

    // 2. Check the size before mapping — zero or tiny files will fault
    LARGE_INTEGER sizeLi{};
    if (!GetFileSizeEx(file.GetHandle(), &sizeLi) ||
        sizeLi.QuadPart < static_cast<LONGLONG>(sizeof(IMAGE_DOS_HEADER))) {
        Logger::getInstance()->log(Level::FAILED, "DiskImage: file too small");
        return;
    }
    size_t fileSize = static_cast<size_t>(sizeLi.QuadPart);

    // 3. Create a read-only mapping of the file
    ScopedHandle mapping( CreateFileMappingW(file.GetHandle(), nullptr, PAGE_READONLY, 0, 0, nullptr) );
    if (!mapping.valid()) {
        Logger::getInstance()->log(Level::FAILED, "DiskImage: CreateFileMapping failed");
        return;
    }

    // 4. Map a view — now the file's bytes appear in OUR address space
    const std::byte* view = reinterpret_cast<const std::byte*>(
        MapViewOfFile(mapping.GetHandle(), FILE_MAP_READ, 0, 0, 0));
    if (!view) {
        Logger::getInstance()->log(Level::FAILED, "DiskImage: MapViewOfFile failed");
        return;
    }

    // 5. Parse the headers out of the mapped view
    loaded = parse(view, fileSize);

    // 6. We copied everything into our fields — release the mapping now.
    UnmapViewOfFile(view);
    // ScopedHandles close the mapping handle, then the file handle, as they unwind.
}

bool DiskImage::parse(const std::byte* base, size_t fileSize)
{
    // DOS header
    std::memcpy(&DOS_Header, base, sizeof(DOS_Header));
    if (DOS_Header.e_magic != IMAGE_DOS_SIGNATURE) {
        validSignature = false;
        return true;                 // read fine, just not a PE — a detection
    }

    // NT headers — bound e_lfanew against the file size first
    LONG lfanew = DOS_Header.e_lfanew;
    if (lfanew <= 0 ||
        static_cast<size_t>(lfanew) + sizeof(IMAGE_NT_HEADERS64) > fileSize) {
        validSignature = false;
        return true;
    }
    std::memcpy(&NT_Headers, base + lfanew, sizeof(NT_Headers));
    if (NT_Headers.Signature != IMAGE_NT_SIGNATURE) {
        validSignature = false;
        return true;
    }

    // Section headers — bound the count AND the total span against the file
    WORD count = NT_Headers.FileHeader.NumberOfSections;
    if (count == 0 || count > 96) {
        validSignature = false;
        return true;
    }
    size_t sectionsOffset = static_cast<size_t>(lfanew) + sizeof(IMAGE_NT_HEADERS64);
    if (sectionsOffset + static_cast<size_t>(count) * sizeof(IMAGE_SECTION_HEADER) > fileSize) {
        validSignature = false;
        return true;
    }
    SectionHeaders.resize(count);
    std::memcpy(SectionHeaders.data(), base + sectionsOffset,
                static_cast<size_t>(count) * sizeof(IMAGE_SECTION_HEADER));

    validSignature = true;
    return true;
}

std::optional<DWORD> DiskImage::rvaToFileOffset(DWORD rva) const
{
    // Case 1: RVA before the first section lies in the headers,
    // where file offset and RVA coincide.
    if (!SectionHeaders.empty() && rva < SectionHeaders[0].VirtualAddress)
        return rva;

    // Case 2: find the section that contains the RVA
    for (const auto& s : SectionHeaders) {
        DWORD start = s.VirtualAddress;
        DWORD end   = s.VirtualAddress + s.Misc.VirtualSize;
        if (rva >= start && rva < end) {
            if (s.SizeOfRawData == 0)
                return std::nullopt;        // BSS: no bytes on disk, no valid offset
            return s.PointerToRawData + (rva - s.VirtualAddress);
        }
    }
    return std::nullopt;                     // not in any section
}