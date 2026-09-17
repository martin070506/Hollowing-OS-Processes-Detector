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

        
        PHANDLE GetPHandle() ;//method isnt const but changes nothing, although it returns a pointer to the handle, which can be used to modify the handle UNSAFE
        HANDLE GetHandle() const ;
        bool valid() const ;
        void reset();
        

};