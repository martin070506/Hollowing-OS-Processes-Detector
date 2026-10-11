#include "PeHeaders.h"

std::optional<ParsedPe> parsePe(const ByteReader& read)
{
    ParsedPe out;

    // DOS header
    if (!read(0, &out.dos, sizeof(out.dos)))
        return std::nullopt;                       // genuine read failure
    if (out.dos.e_magic != IMAGE_DOS_SIGNATURE) {
        out.signaturesValid = false;
        return out;                                // read fine, not a PE — detection
    }

    // NT headers (bound e_lfanew)
    LONG lfanew = out.dos.e_lfanew;
    if (lfanew <= 0 || lfanew > 0x1000) {
        out.signaturesValid = false;
        return out;
    }
    if (!read(static_cast<size_t>(lfanew), &out.nt, sizeof(out.nt)))
        return std::nullopt;
    if (out.nt.Signature != IMAGE_NT_SIGNATURE) {
        out.signaturesValid = false;
        return out;
    }

    // Section headers (bound the count)
    WORD count = out.nt.FileHeader.NumberOfSections;
    if (count == 0 || count > 96) {
        out.signaturesValid = false;
        return out;
    }
    size_t sectionsOffset = static_cast<size_t>(lfanew) + sizeof(IMAGE_NT_HEADERS64);
    out.sections.resize(count);
    if (!read(sectionsOffset, out.sections.data(),
              static_cast<size_t>(count) * sizeof(IMAGE_SECTION_HEADER)))
        return std::nullopt;

    out.signaturesValid = true;
    return out;
}