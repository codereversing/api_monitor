#pragma comment (lib, "Ws2_32.lib")

#ifdef _M_IX86
#ifdef _DEBUG
#pragma comment(lib, "libprotobuf_x86d.lib")
#else
#pragma comment(lib, "libprotobuf_x86.lib")
#endif

#elif defined _M_AMD64
#ifdef _DEBUG
#pragma comment(lib, "libprotobuf_x64d.lib")
#else
#pragma comment(lib, "libprotobuf_x64.lib")
#endif

#else
#error "Unsupported platform"
#endif

#define WIN32_LEAN_AND_MEAN

#include <windows.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdlib.h>
#include <stdio.h>

#include "Hooks.h"

#include "monitor.pb.h"

#define DEFAULT_PORT "4567"

SOCKET Initialize(WSADATA *pWsaData)
{
    int iResult = WSAStartup(MAKEWORD(2,2), pWsaData);
    if (iResult != 0)
    {
        printf("WSAStartup failed. Error = %X\n", iResult);
        return INVALID_SOCKET;
    }

    struct addrinfo *pResult = NULL;
    struct addrinfo hints = { 0 };
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_PASSIVE;

    iResult = getaddrinfo(NULL, DEFAULT_PORT, &hints, &pResult);
    if (iResult != 0)
    {
        printf("getaddrinfo failed. Error = %X\n", iResult);
        WSACleanup();
        return INVALID_SOCKET;
    }

    SOCKET sckListen = socket(pResult->ai_family, pResult->ai_socktype, pResult->ai_protocol);
    if (sckListen == INVALID_SOCKET)
    {
        printf("socket failed with error: %ld\n", WSAGetLastError());
        freeaddrinfo(pResult);
        WSACleanup();
        return INVALID_SOCKET;
    }

    iResult = bind(sckListen, pResult->ai_addr, (int)pResult->ai_addrlen);
    if (iResult == SOCKET_ERROR)
    {
        printf("bind failed. Error = %X\n", WSAGetLastError());
        freeaddrinfo(pResult);
        closesocket(sckListen);
        WSACleanup();
        return INVALID_SOCKET;
    }

    freeaddrinfo(pResult);

    iResult = listen(sckListen, SOMAXCONN);
    if (iResult == SOCKET_ERROR) {
        printf("listen failed. Error = %X\n", WSAGetLastError());
        closesocket(sckListen);
        WSACleanup();
        return INVALID_SOCKET;
    }

    SOCKET sckClient = accept(sckListen, NULL, NULL);
    if (sckClient == INVALID_SOCKET)
    {
        printf("accept failed. Error = %X\n", WSAGetLastError());
        closesocket(sckListen);
        WSACleanup();
        return INVALID_SOCKET;
    }

    closesocket(sckListen);

    return sckClient;
}

void Shutdown(SOCKET sckClient)
{
    int iResult = shutdown(sckClient, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed. Error = %X\n", WSAGetLastError());
    }

    closesocket(sckClient);
    WSACleanup();
}

DWORD WINAPI SocketThread(LPVOID lpParameter)
{
    WSADATA wsaData;
    
    SOCKET sckClient = Initialize(&wsaData);
    if(sckClient != INVALID_SOCKET)
    {
        InitializeHook(sckClient);
        DWORD_PTR dwAddress = 0;
        int iResult = 0;
        do
        {
            int iBuffSize = 0;
            iResult = recv(sckClient, (char *)&iBuffSize, sizeof(int), 0);
            char *pBuffer = (char *)malloc(iBuffSize * sizeof(char));
            iResult = recv(sckClient, pBuffer, iBuffSize, 0);

            ApiMonitor::ProtoBuf::MonitorMessage mReceivedMessage;
            mReceivedMessage.ParseFromArray(pBuffer, iBuffSize);
            if(mReceivedMessage.has_biscontinue())
            {
                SetEvent(hWaitEvent);
            }
            else if(mReceivedMessage.has_maddhook())
            {
                (void)AddHook(mReceivedMessage.maddhook().uihookid(),
                    mReceivedMessage.maddhook().strdllname().c_str(),
                    mReceivedMessage.maddhook().strfunctionname().c_str(),
                    mReceivedMessage.maddhook().uinumparameters(), &dwAddress);
            }
            else if(mReceivedMessage.has_mremovehook())
            {
                (void)RemoveHook(mReceivedMessage.mremovehook().uihookid(), dwAddress);
            }

            free(pBuffer);
        } while(iResult > 0);

        Shutdown(sckClient);
        ShutdownHook();

    }

    return 0;
}

int APIENTRY DllMain(HMODULE hModule, DWORD Reason, LPVOID Reserved)
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    switch(Reason)
    {
    case DLL_PROCESS_ATTACH:
        {
        DWORD dwThreadId = 0;
        HANDLE hThread = CreateThread(NULL, 0, SocketThread, NULL, 0, &dwThreadId);
        }
        break;

    case DLL_PROCESS_DETACH:
        google::protobuf::ShutdownProtobufLibrary();
        break;

    case DLL_THREAD_ATTACH:
    case DLL_THREAD_DETACH:
        break;
    }

    return TRUE;
}