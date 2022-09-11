#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>

char ProcessName[] = "CoDWaW.exe";
char HealthOpCode[] = "\x8B\xD1\x2B\xD3\x90\x90\x90\x90\x90\x90";
char HealthSig[] = "\x8B\xD1\x2B\xD3\x89\x96\x00\x00\x00\x00";
char HealthMask[] = "xxxxxx????";

MODULEINFO GetModuleInfo(char *szModule)
{
	MODULEINFO modInfo = {0};
	HMODULE hModule = GetModuleHandle(szModule);
	if (hModule != 0)
	
		GetModuleInformation(GetCurrentProcess(), hModule, &modInfo, sizeof(MODULEINFO));
	return modInfo;
}

void WriteToMemory(DWORD addressToWrite, char *valueToWrite, int numberOfBytes)
{
	unsigned long old_protection;
	VirtualProtect((LPVOID)addressToWrite, numberOfBytes, PAGE_EXECUTE_READWRITE, &old_protection);
	memcpy((LPVOID)addressToWrite, valueToWrite, numberOfBytes);
	VirtualProtect((LPVOID)addressToWrite, numberOfBytes, old_protection, NULL);
}

DWORD FindPattern(char* module, char* pattern, char* mask)
{
	MODULEINFO mInfo = GetModuleInfo(module);
	DWORD base = (DWORD)mInfo.lpBaseOfDll;
	DWORD size = (DWORD)mInfo.SizeOfImage;
	DWORD patternLength = (DWORD)strlen(mask);

	for (DWORD i = 0; i < size - patternLength; i++)
	{
		bool found = true;
		for (DWORD j = 0; j < patternLength; j++)
		{
			found &= mask[j] == '?' || pattern[j] == *(char*)(base+i+j);
		}
		if (found)
			return base+i;
	}
	return NULL;
}

BOOL WINAPI DllMain(HINSTANCE hinstDll, DWORD fdwReason, LPVOID lpReserved)
{
	if (fdwReason == DLL_PROCESS_ATTACH)
	{
		DWORD healthAddress = FindPattern(ProcessName, HealthSig, HealthMask);
		WriteToMemory(healthAddress, HealthOpCode, strlen(HealthMask));
	}
}