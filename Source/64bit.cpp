#include <Windows.h>
#include <iostream>
#include <hde64.h>

INT main() {

	// 64bit version

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

	hde64s instruction_context = { 0x0 };
	SIZE_T trampoline_size = 0x0;
	while (trampoline_size < 0xc) trampoline_size += hde64_disasm((LPVOID)(lpMessageBoxW + trampoline_size), &instruction_context);

	LPBYTE trampoline_buffer = (LPBYTE)HeapAlloc(GetProcessHeap(), 0x8, trampoline_size);
	if (!ReadProcessMemory(GetCurrentProcess(), lpMessageBoxW, trampoline_buffer, trampoline_size, NULL)) {
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("ReadProcessMemory() failed with %d\n", GetLastError());
		return 0x0;
	}

	SIZE_T iterator = 0x0;
	SIZE_T fixed_trampoline_size = trampoline_size;

	// fixing rip-relative addressing issues
	while (iterator < trampoline_size) {
		SIZE_T instruction_size = hde64_disasm((LPVOID)(trampoline_buffer + iterator), &instruction_context);
		if (instruction_context.opcode == 0x39 && !instruction_context.modrm_mod && instruction_context.modrm_rm == 0x5) {
			BYTE fixed_cmp[] = {
				0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rax, absolute_address
				0x48, 0x81, 0x38, 0x0, 0x0, 0x0, 0x0 // cmp DWORD PTR[rax], 0x0
			};
			*(DWORD64*)(fixed_cmp + 0x2) = (DWORD64)lpMessageBoxW + iterator + instruction_size + instruction_context.disp.disp32;
			
			fixed_trampoline_size += ((0x11 - instruction_size));
			instruction_size = 0x11;
			trampoline_buffer = (LPBYTE)HeapReAlloc(GetProcessHeap(), 0x8, trampoline_buffer, fixed_trampoline_size);
			if (!trampoline_buffer) {
				HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
				FreeLibrary(user32);
				printf_s("HeapReAlloc() failed with %d\n", GetLastError());
				return 0x0;
			}

			CopyMemory(trampoline_buffer + iterator, fixed_cmp, 0x11);
		}
		iterator += instruction_size;
	}

	LPBYTE new_return_address = (LPBYTE)VirtualAlloc(0x0, 0x14, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!new_return_address) {
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("VirtualAlloc(1) failed with %d\n", GetLastError());
		return 0x0;
	}

	BYTE shellcode0x0[] = {
		0x48, 0x31, 0xC0, // xor rax, rax
		0xb8, 0x0, 0x0, 0x0, 0x0, // mov eax, new_return_value
		0x48, 0xb9, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rcx, org_return_address
		0xff, 0xe1, // jmp rcx
	};

	// ==========================================================
	*(DWORD32*)(shellcode0x0 + 0x4) = IDYES; // update the return value as you like in this example we have a yes/no message so the return value can be either IDYES or IDNO depending on the button you click
	// =========================================================


	if (!WriteProcessMemory(GetCurrentProcess(), new_return_address, shellcode0x0, 0x14, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(1) failed with %d\n", GetLastError());
		return 0x0;
	}
	
	LPBYTE proxy = (LPBYTE)VirtualAlloc(0x0, fixed_trampoline_size + 52, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
	if (!proxy) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("VirtualAlloc(2) failed with %d\n", GetLastError());
		return 0x0;
	}

	DWORD64 org_return_address = 0x0;
	BYTE shellcode0x1[] = {
		0x48, 0x8b, 0x4, 0x24, // mov rax, [rsp]
		0x48, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rbx, &org_return_address
		0x48, 0x89, 0x3, // mov [rbx], rax
		0x48, 0xbb, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rbx, new_return_address + 0xa
		0x48, 0x89, 0x3, // mov [rbx], rax
		0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rax, new_return_address
		0x48, 0x89, 0x04, 0x24, // mov [rsp], rax
	};
	*(DWORD64*)(shellcode0x1 + 0x6) = (DWORD64)&org_return_address;
	*(DWORD64*)(shellcode0x1 + 0x13) = (DWORD64)(new_return_address + 0xa);
	*(DWORD64*)(shellcode0x1 + 0x20) = (DWORD64)new_return_address;

	if (!WriteProcessMemory(GetCurrentProcess(), proxy, shellcode0x1, 44, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(2) failed with %d\n", GetLastError());
		return 0x0;
	}

	if (!WriteProcessMemory(GetCurrentProcess(), proxy + 44, trampoline_buffer, fixed_trampoline_size, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(3) failed with %d\n", GetLastError());
		return 0x0;
	}

	BYTE x64_jmp[] = {
		0x48, 0xb8, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, // mov rax, MessageBoxW + trampoline_size
		0xff, 0xe0 // jmp rax
	};
	*(DWORD64*)(x64_jmp + 0x2) = (DWORD64)(lpMessageBoxW + trampoline_size);
	if (!WriteProcessMemory(GetCurrentProcess(), proxy +  fixed_trampoline_size + 44, x64_jmp, 0xc, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(4) failed with %d\n", GetLastError());
		return 0x0;
	}

	DWORD old_protection = 0x0;
	if (!VirtualProtect(lpMessageBoxW, 0xc, PAGE_EXECUTE_READWRITE, &old_protection)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("VirtualProtect(1) failed with %d\n", GetLastError());
		return 0x0;
	}

	*(DWORD64*)(x64_jmp + 0x2) = (DWORD64)proxy;
	if (!WriteProcessMemory(GetCurrentProcess(), lpMessageBoxW, x64_jmp, 0xc, NULL)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("WriteProcessMemory(5) failed with %d\n", GetLastError());
		return 0x0;
	}

	DWORD __old_protection = 0x0;
	if (!VirtualProtect(lpMessageBoxW, 0xc, old_protection, &__old_protection)) {
		VirtualFree(new_return_address, 0x0, MEM_RELEASE);
		VirtualFree(proxy, 0x0, MEM_RELEASE);
		HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
		FreeLibrary(user32);
		printf_s("VirtualProtect(2) failed with %d\n", GetLastError());
		return 0x0;
	}

	choice = ((INT(__stdcall*)(HWND, LPCWSTR, LPCWSTR, UINT))lpMessageBoxW)(0, L"click a button", L"Test", MB_ICONINFORMATION | MB_YESNO);
	printf_s("after : %s\n", choice == IDYES ? "yes" : "no");

	VirtualFree(new_return_address, 0x0, MEM_RELEASE);
	VirtualFree(proxy, 0x0, MEM_RELEASE);
	HeapFree(GetProcessHeap(), 0x0, trampoline_buffer);
	FreeLibrary(user32);

	return 0x0;
}