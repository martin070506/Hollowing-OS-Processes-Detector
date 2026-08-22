#include "ScopedHandle.h"

ScopedHandle::ScopedHandle() : h_(nullptr) {}
ScopedHandle::ScopedHandle(HANDLE handle) : h_(handle) {}
ScopedHandle::~ScopedHandle() {
    reset();
}

ScopedHandle::ScopedHandle(const ScopedHandle&) =delete; // non-copyable (regular reference)
ScopedHandle& ScopedHandle::operator=(const ScopedHandle&) =delete; //(regular reference)

HANDLE ScopedHandle::GetHandle() const {
    return h_;
}
bool ScopedHandle::valid() const {
    return (h_ != nullptr && h_ != INVALID_HANDLE_VALUE);
}
void ScopedHandle::reset() {
    if (valid()) {
        CloseHandle(h_);
        h_ = nullptr;
    }
    else {
        h_ = nullptr;
    }
}
explicit ScopedHandle::operator bool() const {
    return valid();
}