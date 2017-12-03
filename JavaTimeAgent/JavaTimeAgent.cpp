// JavaTimeAgent.cpp : 定义 DLL 应用程序的导出函数。
//


#include <stdio.h>
#include <Windows.h>

bool hooked = false;
DWORD d = 0;
ULONG64 u1 = 0;
ULONG64 u2 = 0;
PVOID pfn;
void WINAPI hook(LPFILETIME ft)
{
	SYSTEMTIME st = { 0 };
	GetSystemTime(&st);
	st.wYear = 2017;
	st.wMonth = 1;
	st.wDay = 1;
	SystemTimeToFileTime(&st, ft);

}
void DoHook()
{
	HMODULE hm=LoadLibraryA("kernelbase.dll");
	pfn=GetProcAddress(hm,"GetSystemTimeAsFileTime");
	VirtualProtect(pfn, 0x1000, PAGE_EXECUTE_READWRITE, &d);
#ifdef WIN64
	BYTE shellcode[] = 
	{ 
		0x48, 0xb8,               //mov rax,
		0, 0, 0, 0, 0, 0, 0, 0,   //hook addr
		0xff, 0xe0                //jmp rax
	};
	BYTE shellcode2[] =
	{
		0x48, 0x33, 0xc0,         //xor rax,rax
		0xc3, 0x00, 0x00          //ret
	};
	
#else
	BYTE shellcode[] =
	{
		0x90, 0xb8,               //mov eax,
		0, 0, 0, 0,               //hook addr
		0xff, 0xe0                //jmp rax
	};
	BYTE shellcode2[] =
	{
		0x33, 0xc0,               //xor eax,eax
		0xc2, 0x08, 0x00          //ret 8
	};
#endif
	PVOID phook = hook;
	memcpy(shellcode + 2, &phook, sizeof(PVOID));
	memcpy(pfn, shellcode, sizeof(shellcode));
	VirtualProtect(pfn, 0x1000, d, &d);
	hm = GetModuleHandleA("java.dll");
	char path[4096] = { 0 };
	d=GetModuleFileNameA(hm, path, 4096);
	for (int i = d; i > 0; i--)
	{
		if (path[i] == '\\')
		{
			path[i] = 0;
			break;
		}
	}
	strcat(path, "\\management.dll");
	hm = LoadLibraryA(path);
	pfn = GetProcAddress(hm, "Java_sun_management_VMManagementImpl_getVmArguments0");
	if (pfn == NULL)
	{
		pfn = GetProcAddress(hm, "_Java_sun_management_VMManagementImpl_getVmArguments0@8");
	}
	if (pfn == NULL)
	{
		pfn = GetProcAddress(hm, "?Java_sun_management_VMManagementImpl_getVmArguments0@@YGPAV_jobjectArray@@PAUJNIEnv_@@PAV_jobject@@@Z");
	}
	VirtualProtect(pfn, 0x1000, PAGE_EXECUTE_READWRITE, &d);
	memcpy(pfn, shellcode2, sizeof(shellcode2));
	VirtualProtect(pfn, 0x1000, d, &d);
}
long WINAPI Agent_OnLoad(PVOID *vm, char *options, void *reserved)
{
	if (!hooked)
	{
		hooked = true;
		DoHook();
	}
	return 0;
}

long WINAPI Agent_OnAttach(PVOID *vm, char *options, void *reserved)
{
	if (!hooked)
	{
		hooked = true;
		DoHook();
	}
	return 0;
}

long WINAPI Agent_OnUnload(PVOID *vm)
{
	return 0;
}

BOOL APIENTRY DllMain(HMODULE hModule,
	DWORD  ul_reason_for_call,
	LPVOID lpReserved
	)
{
	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	case DLL_THREAD_ATTACH:
	case DLL_THREAD_DETACH:
	case DLL_PROCESS_DETACH:
		break;
	}
	return TRUE;
}