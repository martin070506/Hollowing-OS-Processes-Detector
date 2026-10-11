#include "LiveImage.h"
#include "../core/Logger.h"
#include "../core/Level.h"
#include <winternl.h>
#include <cstring>

std::byte* LiveImage::findBaseAddress()
{
    typedef NTSTATUS (NTAPI* NtQueryInformationProcess_t)(
        HANDLE, ULONG, PVOID, ULONG, PULONG);

    auto NtQuery = reinterpret_cast<NtQueryInformationProcess_t>(
        GetProcAddress(GetModuleHandleW(L"ntdll.dll"), "NtQueryInformationProcess"));
    if (!NtQuery) {
        Logger::getInstance()->log(Level::FAILED, "couldn't find NtQueryInformationProcess");
        return nullptr;
    }

    PROCESS_BASIC_INFORMATION pbi{};
    ULONG returnLength = 0;
    NTSTATUS status = NtQuery(_processHandle, 0, &pbi, sizeof(pbi), &returnLength);
    if (!NT_SUCCESS(status)) {
        Logger::getInstance()->log(Level::FAILED, "NtQueryInformationProcess failed");
        return nullptr;
    }

    auto baseOpt = _rm.typeRead<void*>(
        reinterpret_cast<const std::byte*>(pbi.PebBaseAddress) + 0x10);
    if (!baseOpt) {
        Logger::getInstance()->log(Level::FAILED, "couldn't read image base from PEB");
        return nullptr;
    }
    return reinterpret_cast<std::byte*>(*baseOpt);
}

LiveImage::LiveImage(HANDLE h)
    : _rm(h), _processHandle(h), BaseAddress(nullptr),
      DOS_Header{}, NT_Headers{}, validSignature(false), loaded(false)
{
    // --- Step 1: base address ---
    BaseAddress = findBaseAddress();
    if (!BaseAddress) return;                 // genuine failure, loaded stays false

    // --- Step 2: DOS header, check MZ ---
    auto dosOpt = _rm.typeRead<IMAGE_DOS_HEADER>(BaseAddress);
    if (!dosOpt) {
        Logger::getInstance()->log(Level::FAILED, "couldn't read DOS header");
        return;                               // read failure, loaded stays false
    }
    DOS_Header = *dosOpt;
    loaded = true;                            // we read successfully — loaded from here on,
                                              // even if the signatures turn out missing

    if (DOS_Header.e_magic != IMAGE_DOS_SIGNATURE) {
        validSignature = false;
        return;                               // NOT a failure — a detection
    }

    // --- Step 3: NT headers, check PE (bound e_lfanew first) ---
    LONG lfanew = DOS_Header.e_lfanew;
    if (lfanew <= 0 || lfanew > 0x1000) {
        validSignature = false;
        return;
    }
    auto ntOpt = _rm.typeRead<IMAGE_NT_HEADERS64>(BaseAddress + lfanew);
    if (!ntOpt) {
        Logger::getInstance()->log(Level::FAILED, "couldn't read NT headers");
        return;
    }
    NT_Headers = *ntOpt;
    if (NT_Headers.Signature != IMAGE_NT_SIGNATURE) {
        validSignature = false;
        return;                               // detection
    }

    // --- Step 4: section headers (bound the count first) ---
    WORD count = NT_Headers.FileHeader.NumberOfSections;
    if (count == 0 || count > 96) {
        validSignature = false;
        return;
    }
    auto sectionsAddr = BaseAddress + static_cast<size_t>(lfanew) + sizeof(IMAGE_NT_HEADERS64);
    auto rawOpt = _rm.readBuffer(sectionsAddr, count * sizeof(IMAGE_SECTION_HEADER));
    if (!rawOpt) {
        Logger::getInstance()->log(Level::FAILED, "couldn't read section headers");
        return;
    }
    SectionHeaders.resize(count);
    std::memcpy(SectionHeaders.data(), rawOpt->data(),
                count * sizeof(IMAGE_SECTION_HEADER));

    validSignature = true;
}