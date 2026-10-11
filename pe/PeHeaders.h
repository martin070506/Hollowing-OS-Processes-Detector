#pragma once
#include <windows.h>
#include <vector>
#include <optional>
#include <functional>
#include <cstddef>

// The result of a successful parse — the common shape both images expose.
struct ParsedPe {
    IMAGE_DOS_HEADER dos{};
    IMAGE_NT_HEADERS64 nt{};
    std::vector<IMAGE_SECTION_HEADER> sections;
    bool signaturesValid = false;
};

// A "reader": given an offset and a size, copy that many bytes into dest.
// Returns true on a full, successful read. Each image supplies its own.
using ByteReader = std::function<bool(size_t offset, void* dest, size_t size)>;

// Walk the headers using whatever reader is supplied.
// Returns nullopt only on a genuine read failure; a missing signature
// returns a ParsedPe with signaturesValid == false.
std::optional<ParsedPe> parsePe(const ByteReader& read);