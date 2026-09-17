#include "ScopedHandle.h"

ScopedHandle::ScopedHandle() : h_(nullptr) {}
ScopedHandle::ScopedHandle(HANDLE handle) : h_(handle) {}
ScopedHandle::~ScopedHandle() {
    reset();
}



HANDLE ScopedHandle::GetHandle() const {
    return h_;
}
PHANDLE ScopedHandle::GetPHandle()  {
    return &h_;
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
 