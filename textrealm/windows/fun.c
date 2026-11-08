#include <windows.h>

/* Gadget 1: SEH Bypass (pop-pop-ret sequence) */
__declspec(dllexport) void dummy_gadget(void) {
    __asm__(
        "pop %edi\n\t"
        "pop %esi\n\t"
        "ret\n\t"
    );
}

/* Gadget 2: Simple Buffer Overflow (Direct JMP ESP) */
__declspec(dllexport) void jump_esp_gadget(void) {
    __asm__(
        "jmp %esp\n\t"
    );
}

BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved) {
    return TRUE;
}
