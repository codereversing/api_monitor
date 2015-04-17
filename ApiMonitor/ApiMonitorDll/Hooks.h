#pragma once

#include <Windows.h>

#include "monitor.pb.h"

typedef void (WINAPI *pHookFnc)(CONTEXT *pContext);

const bool InitializeHook(SOCKET socket);
const bool ShutdownHook();

const bool AddHook(const DWORD_PTR dwId, const char *pDllName, const char *pFunctionName, const DWORD_PTR dwNumParameters, DWORD_PTR *pOutAddress);
const bool RemoveHook(const DWORD_PTR dwId, const DWORD_PTR dwAddress);

static const bool AddPagePermissionFlag(const DWORD_PTR dwAddress, const DWORD_PTR dwProtectionFlag);
static const bool RemovePagePermissionFlag(const DWORD_PTR dwAddress, const DWORD_PTR dwProtectionFlag);

static LONG CALLBACK ExceptionHandler(EXCEPTION_POINTERS *pExceptionPointers);

static void WINAPI HookFunction(CONTEXT *pContext);

extern HANDLE hWaitEvent;