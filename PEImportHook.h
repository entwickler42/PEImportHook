#ifndef __PE_IMPORT_HOOK
#define __PE_IMPORT_HOOK

#include <windows.h>

#ifdef  DLL_BUILD
#define DLL_EXPORT __declspec(dllexport)
#else   
#define DLL_EXPORT __declspec(dllimport)
#endif

PIMAGE_IMPORT_DESCRIPTOR NamedImageImportDescriptor(LPSTR module, LPSTR libname);
PIMAGE_IMPORT_DESCRIPTOR FirstImageImportDescriptor(HANDLE module);

extern "C" BOOL DLL_EXPORT ReplaceFunctionByName(LPSTR module, LPSTR szDllName, LPSTR szFuntion, DWORD hook_func, DWORD* old_func);
extern "C" BOOL DLL_EXPORT ReplaceFunctionByOrdinal(LPSTR module, LPSTR szDllName, UINT ordinal, DWORD hook_func, DWORD* old_func);

#endif