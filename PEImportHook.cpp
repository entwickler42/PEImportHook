#include "PEImportHook.h"

//-----------------------------------------------------------------------------
PIMAGE_IMPORT_DESCRIPTOR FirstImageImportDescriptor(HANDLE module)
{	
	if(module == NULL)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	PIMAGE_DOS_HEADER hdr_dos  = (PIMAGE_DOS_HEADER)module;

	if(hdr_dos->e_magic != IMAGE_DOS_SIGNATURE)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	PIMAGE_NT_HEADERS32 hdr_pe = (PIMAGE_NT_HEADERS32)((BYTE*)module + hdr_dos->e_lfanew);

	if(hdr_pe->Signature != IMAGE_NT_SIGNATURE)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	if(hdr_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress == 0)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	return (PIMAGE_IMPORT_DESCRIPTOR)((BYTE*)module + hdr_pe->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);
};

//-----------------------------------------------------------------------------
PIMAGE_IMPORT_DESCRIPTOR NamedImageImportDescriptor(HANDLE module, LPSTR libname)
{
	if(module == NULL)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	if(libname == NULL)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	PIMAGE_IMPORT_DESCRIPTOR desc = FirstImageImportDescriptor(module);

	if(desc == NULL)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return NULL;
	}

	PSTR dll_name;

	while(desc->Name != NULL)
	{
		dll_name = (PSTR)(desc->Name + (BYTE*)module);
		if(!stricmp(libname,dll_name)) break;
		desc++;
	}

	return desc->Name == NULL ? NULL : desc;
}

//-----------------------------------------------------------------------------
BOOL ReplaceFunctionByName(LPSTR szModule, LPSTR szDllName, LPSTR szFunction, DWORD hook_func, DWORD* old_func)
{
	BOOL hooked   = FALSE;
	HANDLE module = GetModuleHandle(szModule);

	if(szFunction == NULL)
	{
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return FALSE;
	}

	PIMAGE_IMPORT_DESCRIPTOR desc = NamedImageImportDescriptor(module,szDllName);

	if(desc == NULL)
	{
		#ifdef _DEBUG
		MessageBox(NULL,"Requested DLL not Imported","ERROR",MB_OK|MB_ICONERROR);
		#endif
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return FALSE;
	}

	PIMAGE_THUNK_DATA org_thunk = (PIMAGE_THUNK_DATA)(desc->OriginalFirstThunk + (BYTE*)module);
	PIMAGE_THUNK_DATA adr_thunk = (PIMAGE_THUNK_DATA)(desc->FirstThunk + (BYTE*)module);

	while(org_thunk->u1.Function != NULL)
	{		
		if ( (org_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) != IMAGE_ORDINAL_FLAG )
		{
			// Import by Name
			PIMAGE_IMPORT_BY_NAME cur_imp = (PIMAGE_IMPORT_BY_NAME)((BYTE*)module + org_thunk->u1.AddressOfData);
			
			if(!stricmp(szFunction,(LPSTR)cur_imp->Name))
			{
				MEMORY_BASIC_INFORMATION mbi_thunk ;

            VirtualQuery(adr_thunk, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION)) ;
				VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, PAGE_READWRITE, &mbi_thunk.Protect);

				*old_func = adr_thunk->u1.Function;
				adr_thunk->u1.Function = hook_func;

				DWORD dwOldProtect ;
				VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &dwOldProtect);

				hooked = TRUE;

				break;
			}
		}
		org_thunk++;	adr_thunk++;
	}

	return hooked;
}

//-----------------------------------------------------------------------------
BOOL ReplaceFunctionByOrdinal(LPSTR szModule, LPSTR szDllName, UINT ordinal, DWORD hook_func, DWORD* old_func)
{
	BOOL hooked		= FALSE;
	HANDLE module  = GetModuleHandle(szModule);

	PIMAGE_IMPORT_DESCRIPTOR desc = NamedImageImportDescriptor(module,szDllName);

	if(desc == NULL)
	{
		#ifdef _DEBUG
		MessageBox(NULL,"Requested DLL not Imported","ERROR",MB_OK|MB_ICONERROR);
		#endif
		SetLastErrorEx ( ERROR_INVALID_PARAMETER , SLE_ERROR ) ;
		return FALSE;
	}

	PIMAGE_THUNK_DATA org_thunk = (PIMAGE_THUNK_DATA)(desc->OriginalFirstThunk + (BYTE*)module);
	PIMAGE_THUNK_DATA adr_thunk = (PIMAGE_THUNK_DATA)(desc->FirstThunk + (BYTE*)module);

	DWORD dwOrdinal = IMAGE_ORDINAL_FLAG | ordinal;

	while(org_thunk->u1.Function != NULL)
	{		
		if ( (org_thunk->u1.Ordinal & IMAGE_ORDINAL_FLAG) == IMAGE_ORDINAL_FLAG )
		{
			if(org_thunk->u1.Ordinal == dwOrdinal)
			{
				MEMORY_BASIC_INFORMATION mbi_thunk ;

            VirtualQuery(adr_thunk, &mbi_thunk, sizeof(MEMORY_BASIC_INFORMATION)) ;
				VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, PAGE_READWRITE, &mbi_thunk.Protect);

				*old_func = adr_thunk->u1.Function;
				adr_thunk->u1.Function = hook_func;

				DWORD dwOldProtect ;
				VirtualProtect(mbi_thunk.BaseAddress, mbi_thunk.RegionSize, mbi_thunk.Protect, &dwOldProtect);

				hooked = TRUE;

				break;
			}
		}
		org_thunk++;	adr_thunk++;
	}

	return hooked;
}
