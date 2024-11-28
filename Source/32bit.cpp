#include <Windows.h>
#include <iostream>
#include <hde32.h>

INT main() {

	// 32bit version

	HMODULE user32 = LoadLibraryExW(L"user32.dll", NULL, LOAD_LIBRARY_SEARCH_SYSTEM32);
	if (!user32) {
		printf_s("LoadLibraryExW() failed with %d\n", GetLastError());
		return 0x0;
	}

	LPBYTE lpMessageBoxW = (LPBYTE)GetProcAddress(user32, "MessageBoxW");
	if (!lpMessageBoxW) {
		FreeLibrary(user32);
		printf_s("GetProcAddress() failed with %d\n", GetLastError());
		return 0x0;
	}

	// before ==================================================================================================================================

	INT choice = ((INT(__stdcall*)(HWND, LPCWSTR, LPCWSTR, UINT))lpMessageBoxW)(0, L"click a button", L"Test", MB_ICONINFORMATION | MB_YESNO);
	printf_s("before : %s\n", choice == IDYES ? "yes" : "no");

	// =========================================================================================================================================
	
	hde32s instruction_context = { 0x0 };
	SIZE_T trampoline_size = 0x0;

	while (trampoline_size < 0x5) trampoline_size += hde32_disasm((LPVOID)(lpMessageBoxW + trampoline_size), &instruction_context);
	
	LPBYTE proxy = (LPBYTE)VirtualAlloc(0x0, 0x1b + trampoline_size, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!proxy) {
		FreeLibrary(user32);
		printf_s("VirtualAlloc() failed with %d\n", GetLastError());
		return 0x0;
	}

	LPBYTE trampoline_buffer = (LPBYTE)HeapAlloc(GetProcessHeap(), 0x8, trampoline_size);
	if (!trampoline_buffer) {
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("HeapAlloc() failed with %d\n", GetLastError());
		return 0x0;
	}
	if (!ReadProcessMemory(GetCurrentProcess(), lpMessageBoxW, trampoline_buffer, trampoline_size, NULL)) {
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("ReadProcessMemory() failed with %d\n", GetLastError());
		return 0x0;
	}

	BYTE shellcode0x1[] = {
		0xb8, 0x0, 0x0, 0x0, 0x0, // mov eax, new return value
		0xb9, 0x0, 0x0, 0x0, 0x0, // mov ecx, original_return_address
		0xff, 0xe1 // jmp ecx
	};
	
	// -----------------------------------------------------------------------

	*(DWORD32*)(shellcode0x1 + 0x1) = IDYES; // update the return value as you like in this example we have a yes/no message so the return value can be either IDYES or IDNO depending on the button you click
	
	// -----------------------------------------------------------------------

	LPBYTE new_return_address = (LPBYTE)VirtualAlloc(0x0, 0xc, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!new_return_address) {
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("VirtualAlloc(1) failed with %d\n", GetLastError());
		return 0x0;
	}
	if (!WriteProcessMemory(GetCurrentProcess(), new_return_address, shellcode0x1, 0xc, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(1) failed with %d\n", GetLastError());
		return 0x0;
	}

	DWORD_PTR org_return_address = 0x0;
	
	BYTE shellcode0x0[] = { 
		0x8b, 0x04, 0x24, // mov eax, [esp]
		0x89, 0x05, 0x0, 0x0, 0x0, 0x0, // mov [&org_return_address], eax
		0x89, 0x05, 0x0, 0x0, 0x0, 0x0, // mov [new_return_address + 0x6], eax
		0xc7, 0x04, 0x24, 0x0, 0x0, 0x0, 0x0, // mov [esp], new_return_address
	};
	
	*(DWORD32*)(shellcode0x0 + 0x5) = (DWORD32)&org_return_address;
	*(DWORD32*)(shellcode0x0 + 0xb) = (DWORD32)(new_return_address + 0x6);
	*(DWORD32*)(shellcode0x0 + 0x12) = (DWORD32)new_return_address;
	if (!WriteProcessMemory(GetCurrentProcess(), proxy, shellcode0x0, 0x16, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(2) failed with %d\n", GetLastError());
		return 0x0;
	}
	if (!WriteProcessMemory(GetCurrentProcess(), proxy + 0x16, trampoline_buffer, trampoline_size, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(3) failed with %d\n", GetLastError());
		return 0x0;
	}
	BYTE x86_jmp[] = { 0xe9, 0x0, 0x0, 0x0, 0x0 };
	*(DWORD32*)(x86_jmp + 0x1) = (DWORD32)((DWORD32)(lpMessageBoxW + trampoline_size) - (DWORD32)(proxy + 0x1b + trampoline_size));
	if (!WriteProcessMemory(GetCurrentProcess(), proxy + 0x16 + trampoline_size, x86_jmp, 0x5, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(4) failed with %d\n", GetLastError());
		return 0x0;
	}

	DWORD old_protection = 0x0;
	VirtualProtect(proxy, 0x1b + trampoline_size, PAGE_EXECUTE_READ, &old_protection);

	if (!VirtualProtect(lpMessageBoxW, 0x5, PAGE_EXECUTE_READWRITE, &old_protection)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("VirtualProtect() failed with %d\n", GetLastError());
		return 0x0;
	}

	*(DWORD32*)(x86_jmp + 0x1) = (DWORD32)((DWORD32)proxy - (DWORD32)(lpMessageBoxW + 0x5));
	if (!WriteProcessMemory(GetCurrentProcess(), lpMessageBoxW, x86_jmp, 0x5, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(5) failed with %d\n", GetLastError());
		return 0x0;
	}

	DWORD __old_protection = 0x0;
	if (!VirtualProtect(lpMessageBoxW, 0x5, old_protection, &__old_protection)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		FreeLibrary(user32);
		printf_s("VirtualProtect(1) failed with %d\n", GetLastError());
		return 0x0;
	}

	// after ==================================================================================================================================

	choice = ((INT(__stdcall*)(HWND, LPCWSTR, LPCWSTR, UINT))lpMessageBoxW)(0, L"click a button", L"Test", MB_ICONINFORMATION | MB_YESNO);
	printf_s("after : %s\n", choice == IDYES ? "yes" : "no");

	// =========================================================================================================================================

	VirtualFree(new_return_address, 0x0, MEM_RELEASE);
	HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
	VirtualFree(proxy, 0x0, MEM_RELEASE);
	FreeLibrary(user32);
	return 0x0;
}