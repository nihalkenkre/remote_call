#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>

#include "remote_call.x64.bin.h"

#include <stdio.h>
#include <stddef.h>

typedef struct _global_data
{
    DWORD64 dwWriteFile;
    DWORD64 dwReadFile;
    DWORD64 dwCreateToolhelp32Snapshot;
    DWORD64 dwProcess32First;
    DWORD64 dwProcess32Next;
    DWORD64 dwThread32First;
    DWORD64 dwThread32Next;
    DWORD64 dwOpenProcess;
    DWORD64 dwOpenThread;
    DWORD64 dwCloseHandle;
    DWORD64 dwVirtualAllocEx;
    DWORD64 dwVirtualFreeEx;
    DWORD64 dwWriteProcessMemory;
    DWORD64 dwReadProcessMemory;
    DWORD64 dwGetThreadContext;
    DWORD64 dwSuspendThread;
    DWORD64 dwResumeThread;
    DWORD64 dwSleep;
    DWORD64 dwLoadLibraryA;

    DWORD64 dwStdOutHnd;
    DWORD64 dwStdInHnd;

    DWORD64 dwNtContinue;
    DWORD64 dwRtlRemoteCall;
} GLOBAL_DATA, *PGLOBAL_DATA;

int main(void)
{
    GLOBAL_DATA globalData = {0};

    HMODULE hKernel32 = GetModuleHandleA("kernel32");
    globalData.dwWriteFile = (DWORD64)GetProcAddress(hKernel32, "WriteFile");
    globalData.dwReadFile = (DWORD64)GetProcAddress(hKernel32, "ReadFile");
    globalData.dwCreateToolhelp32Snapshot = (DWORD64)GetProcAddress(hKernel32, "CreateToolhelp32Snapshot");
    globalData.dwProcess32First = (DWORD64)GetProcAddress(hKernel32, "Process32First");
    globalData.dwProcess32Next = (DWORD64)GetProcAddress(hKernel32, "Process32Next");
    globalData.dwThread32First = (DWORD64)GetProcAddress(hKernel32, "Thread32First");
    globalData.dwThread32Next = (DWORD64)GetProcAddress(hKernel32, "Thread32Next");
    globalData.dwOpenProcess = (DWORD64)GetProcAddress(hKernel32, "OpenProcess");
    globalData.dwOpenThread = (DWORD64)GetProcAddress(hKernel32, "OpenThread");
    globalData.dwCloseHandle = (DWORD64)GetProcAddress(hKernel32, "CloseHandle");
    globalData.dwVirtualAllocEx = (DWORD64)GetProcAddress(hKernel32, "VirtualAllocEx");
    globalData.dwVirtualFreeEx = (DWORD64)GetProcAddress(hKernel32, "VirtualFreeEx");
    globalData.dwWriteProcessMemory = (DWORD64)GetProcAddress(hKernel32, "WriteProcessMemory");
    globalData.dwReadProcessMemory = (DWORD64)GetProcAddress(hKernel32, "ReadProcessMemory");
    globalData.dwGetThreadContext = (DWORD64)GetProcAddress(hKernel32, "GetThreadContext");
    globalData.dwSuspendThread = (DWORD64)GetProcAddress(hKernel32, "SuspendThread");
    globalData.dwResumeThread = (DWORD64)GetProcAddress(hKernel32, "ResumeThread");
    globalData.dwSleep = (DWORD64)GetProcAddress(hKernel32, "Sleep");
    globalData.dwLoadLibraryA = (DWORD64)GetProcAddress(hKernel32, "LoadLibraryA");

    globalData.dwStdOutHnd = (DWORD64)GetStdHandle(STD_OUTPUT_HANDLE);
    globalData.dwStdInHnd = (DWORD64)GetStdHandle(STD_INPUT_HANDLE);

    HMODULE hNtdll = GetModuleHandleA("ntdll");

    globalData.dwNtContinue = (DWORD64)GetProcAddress(hNtdll, "NtContinue");
    globalData.dwRtlRemoteCall = (DWORD64)GetProcAddress(hNtdll, "RtlRemoteCall");

    HANDLE hTargetProc = GetCurrentProcess();

    LPVOID lpvRemoteCall = VirtualAllocEx(hTargetProc, 0, remote_call_x64_len + 240, MEM_RESERVE | MEM_COMMIT, PAGE_EXECUTE_READWRITE);
    if (lpvRemoteCall == NULL)
    {
        printf("VirtualAlloc failed, %d\n", GetLastError());
        return 1;
    }

    if (!WriteProcessMemory(hTargetProc, lpvRemoteCall, remote_call_x64, remote_call_x64_len, NULL))
    {
        printf("WriteProcessMemory failed, remote_call %d\n", GetLastError());
        return 2;
    }

    if (!WriteProcessMemory(hTargetProc, (LPVOID)((ULONG_PTR)lpvRemoteCall + remote_call_x64_len), &globalData, sizeof(globalData), NULL))
    {
        printf("WriteProcessMemory failed, global data  %d\n", GetLastError());
        return 3;
    }

    HANDLE hThread = CreateRemoteThread(hTargetProc, NULL, 0, (LPTHREAD_START_ROUTINE)lpvRemoteCall, NULL, 0, NULL);

    if (hThread != NULL)
    {
        WaitForSingleObject(hThread, INFINITE);
        CloseHandle(hThread);
    }

    return 0;
}