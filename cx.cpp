// cx.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>


typedef struct _LSA_UNICODE_STRING {
	USHORT Length;
	USHORT MaximumLength;
	PWSTR  Buffer;
} LSA_UNICODE_STRING, *PLSA_UNICODE_STRING, UNICODE_STRING, *PUNICODE_STRING;


__forceinline DWORD __declspec(naked) __stdcall CalcStringHash_asm(WCHAR *pstr)
{
	__asm
	{
		push ebp
			mov ebp, esp
			push edi
			push esi
			push ebx
			
			mov esi, pstr
			xor edi, edi           //clear edi which will store the hash of the module name
loop_modname:
		xor eax, eax           //clear eax
			lodsw                  //read in the next byte of the name
			cmp ax, 0x0061            //some versions of Windows use lower case module names
			jl not_lowercase
			sub ax, 0x20           //if so normalise to uppercase
not_lowercase:
		ror edi, 13            //rotate right our hash value
			add edi, eax           //add the next byte of the name to the hash
			test ax, ax
			jnz  loop_modname
			mov eax, edi
			
			pop ebx
			pop esi
			pop edi
			pop ebp
			retn 4
    }
}


__forceinline  int ror( ULONG eax ,ULONG cl) 
{ 
	eax = (eax>>cl)+(eax<<(32-cl));
	return eax;
}

__forceinline DWORD __stdcall CalcStringHash(WCHAR *pstr)
{
	ULONG v1; // esi@1
	ULONG v2; // edi@1
	ULONG v3; // eax@2
	ULONG v4; // edi@4
	
	v1 = (INT)pstr;
	v2 = 0;
	do
	{
		v3 = *(WORD *)v1;
		v1 += 2;
		if ( (unsigned __int16)v3 >= 97 )
			v3 = ( v3 & 0xFFFF0000 ) | (v3 - 32);
		v4 = ror(v2, 13);
		v2 = v3 + v4;
	}
	while ( (WORD)v3 );
	return v2;
}


__forceinline HANDLE __stdcall bt_GetLoadedDllHandle(WCHAR *DllName)
{
    void *PEB = NULL,
        *Ldr = NULL,
        *Flink = NULL,
        *p = NULL,
        *head = NULL,
        *BaseAddress = NULL,
        *FullDllName = NULL;
	
    DWORD hash = CalcStringHash(DllName);
	
    __asm
    {
        mov eax, fs:[0x30]
			mov PEB, eax
    }
    Ldr = *( ( void ** )( ( unsigned char * )PEB + 0x0c ) );
    Flink = *( ( void ** )( ( unsigned char * )Ldr + 0x14 ) );
    p = Flink;
    head = *(void **)((unsigned char *)p + 4);
    do
    {
        BaseAddress = *( ( void ** )( ( unsigned char * )p + 0x10 ) );
        FullDllName = *( ( void ** )( ( unsigned char * )p + 0x28 ) );
		
        if (FullDllName) //这个 有可能是 NULL
        {
            if (hash == CalcStringHash((WCHAR *)FullDllName))
            {
                return BaseAddress;
            }
        }
        p = *( ( void ** )p);
    }
    while ( p != head);
	
    return NULL;
}


__forceinline int bt_StrCmp(const char *str1, const char *str2)
{
    while (*str1 && *str2)
    {
        if (*str1 != *str2)
            break;
        str1 ++;
        str2 ++;
    }
    return (*str1 - *str2);
}

__forceinline int bt_WcsCmp(const WCHAR *str1, const WCHAR *str2)
{
    while (*str1 && *str2)
    {
        if (*str1 != *str2)
            break;
        str1 ++;
        str2 ++;
    }
    return (*str1 - *str2);
}

__forceinline LPVOID bt_GetProcAddress(HMODULE module, LPCSTR name)
{
    DWORD i;
#if defined _WIN64
    PIMAGE_NT_HEADERS64 ntHeaders  = (PIMAGE_NT_HEADERS64)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#else
    PIMAGE_NT_HEADERS32 ntHeaders  = (PIMAGE_NT_HEADERS32)((LPBYTE)module + ((PIMAGE_DOS_HEADER)module)->e_lfanew);
#endif
    PIMAGE_DATA_DIRECTORY impDir = &ntHeaders->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    PIMAGE_EXPORT_DIRECTORY ied =  (PIMAGE_EXPORT_DIRECTORY)((LPBYTE)module + impDir->VirtualAddress);
	
    for (i = 0; i < ied->NumberOfNames; i++)
    {
        LPDWORD curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfNames + i * sizeof(DWORD));
        if (curName && bt_StrCmp(name, (LPSTR)((LPBYTE)module + *curName)) == 0)
        {
            LPWORD pw = (LPWORD)(((LPBYTE)module) + ied->AddressOfNameOrdinals + i * sizeof(WORD));
            curName = (LPDWORD)(((LPBYTE)module) + ied->AddressOfFunctions + (*pw) * sizeof(DWORD));
            return ((LPBYTE)module + *curName);
        }
    }
	
    return NULL;
}

typedef VOID ( __stdcall * P_RtlInitUnicodeString)(
												   PUNICODE_STRING DestinationString,
												   PCWSTR SourceString
												   );

typedef ULONG (__stdcall *P_LdrLoadDll)(
										__in_opt PWSTR DllPath,
										__in_opt PULONG DllCharacteristics,
										__in PUNICODE_STRING DllName,
										__out PVOID *DllHandle
										);

HANDLE bt_LoadDllW(WCHAR *DllName)
{
    UNICODE_STRING str;
	LPVOID hDll = NULL;
	WCHAR ntdll[] = {L'n',L't',L'd',L'l',L'l',L'.',L'd',L'l',L'l',L'\x0'};
	CHAR str_RtlInitUnicodeString[] = {'R','t','l','I','n','i','t','U','n','i','c','o','d','e','S','t','r','i','n','g','\x0'};
    CHAR str_LdrLoadDll[] = {'L','d','r','L','o','a','d','D','l','l','\x0'};
	HANDLE hNtdll = bt_GetLoadedDllHandle(ntdll);
	if(hNtdll)
	{
		P_RtlInitUnicodeString fnRtlInitUnicodeString = (P_RtlInitUnicodeString)bt_GetProcAddress((HMODULE)hNtdll,str_RtlInitUnicodeString);
		if(fnRtlInitUnicodeString)
		{
			fnRtlInitUnicodeString(&str, DllName);
			P_LdrLoadDll fnLdrLoadDll = (P_LdrLoadDll)bt_GetProcAddress((HMODULE)hNtdll,str_LdrLoadDll);
			if(fnLdrLoadDll)
			{
				fnLdrLoadDll(NULL, 0, &str, &hDll);
			}
		}
	}
    return hDll;
}

void shellcode()
{
	WCHAR dllName[] = {L'u',L'r',L'l',L'm',L'o',L'n',L'.',L'd',L'l',L'l',L'\x0',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'A',L'\x00'};
	HANDLE x = bt_LoadDllW(dllName);
}

int main(int argc, char* argv[])
{
	shellcode();
	getchar();
	return 0;
}

