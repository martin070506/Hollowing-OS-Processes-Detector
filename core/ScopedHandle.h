#pragma once
#include <windows.h>

class ScopedHandle {
    private:
        HANDLE h_ = nullptr;

    public:
        ScopedHandle();
        explicit ScopedHandle(HANDLE handle);
        
        ~ScopedHandle();
        ScopedHandle(ScopedHandle&& o) noexcept; //getting a reference(RVALUE) to the object being moved from
        ScopedHandle& operator=(ScopedHandle&& o) noexcept ; //getting a reference (RVALUE) and doing equals (operator=)
        ScopedHandle(const ScopedHandle&) =delete; // non-copyable (regular reference)
        ScopedHandle& operator=(const ScopedHandle&) =delete; //(regular reference)

        HANDLE GetHandle() const ;
        bool valid() const ;
        void reset();
        explicit operator bool() const ;

};