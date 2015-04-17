#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "Mswsock.lib")
#pragma comment(lib, "AdvApi32.lib")

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

#include "monitor.pb.h"
#include "Common.h"

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
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &pResult);
    if (iResult != 0)
    {
        printf("getaddrinfo failed. Error = %X\n", iResult);
        WSACleanup();
        return INVALID_SOCKET;
    }

    SOCKET sckConnect = INVALID_SOCKET;
    for (struct addrinfo *pResultIter = pResult; pResultIter != NULL; pResultIter = pResultIter->ai_next)
    {
        sckConnect = socket(pResultIter->ai_family, pResultIter->ai_socktype, pResultIter->ai_protocol);
        if (sckConnect == INVALID_SOCKET)
        {
            printf("socket failed. Error = %X\n", WSAGetLastError());
            WSACleanup();
            return INVALID_SOCKET;
        }

        iResult = connect( sckConnect, pResultIter->ai_addr, (int)pResultIter->ai_addrlen);
        if (iResult == SOCKET_ERROR)
        {
            closesocket(sckConnect);
            sckConnect = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(pResult);

    if (sckConnect == INVALID_SOCKET)
    {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return INVALID_SOCKET;
    }

    return sckConnect;
}

void Shutdown(SOCKET sckConnect)
{
    int iResult = shutdown(sckConnect, SD_SEND);
    if (iResult == SOCKET_ERROR)
    {
        printf("shutdown failed. Error = %X\n", WSAGetLastError());
    }

    closesocket(sckConnect);
    WSACleanup();
}

ApiMonitor::ProtoBuf::MonitorMessage ReceiveIncomingMessage(SOCKET sckConnect)
{
    int iBuffSize = 0;
    (void)recv(sckConnect, (char *)&iBuffSize, sizeof(int), 0);

    char *pBuffer = (char *)malloc(iBuffSize * sizeof(char));
    (void)recv(sckConnect, pBuffer, iBuffSize, 0);

    ApiMonitor::ProtoBuf::MonitorMessage mRetMsg;
    mRetMsg.ParseFromArray(pBuffer, iBuffSize);

    return mRetMsg;
}

int main(int argc, char *argv[]) 
{
    GOOGLE_PROTOBUF_VERIFY_VERSION;

    WSADATA wsaData;

    if(argc != 2)
    {
        printf("Usage: %s ProcessId\n", argv[0]);
    }

    SOCKET sckConnect = Initialize(&wsaData);
    if(sckConnect != INVALID_SOCKET)
    {
        ApiMonitor::ProtoBuf::MonitorMessage mOutgoingMessage;
        mOutgoingMessage.mutable_maddhook()->set_uihookid(0x123);
        mOutgoingMessage.mutable_maddhook()->set_strdllname("user32.dll", 10);
        mOutgoingMessage.mutable_maddhook()->set_strfunctionname("MessageBoxA", 11);
        mOutgoingMessage.mutable_maddhook()->set_uinumparameters(4);
        (void)SendOutgoingMessage(sckConnect, &mOutgoingMessage);

        do
        {
            ApiMonitor::ProtoBuf::MonitorMessage mIncomingMessage = ReceiveIncomingMessage(sckConnect);
            assert(mIncomingMessage.mcall().uihookid() == 0x123);

            HWND hWnd = (HWND)mIncomingMessage.mcall().uiparameter(0);
            DWORD_PTR dwTextAddress = (DWORD_PTR)mIncomingMessage.mcall().uiparameter(1);
            DWORD_PTR dwCaptionAddress = (DWORD_PTR)mIncomingMessage.mcall().uiparameter(2);
            UINT uiType = (UINT)mIncomingMessage.mcall().uiparameter(3);
            LPSTR lpTextBuffer[64] = { 0 };
            LPSTR lpTitleBuffer[64] = { 0 };
        
            DWORD dwProcessId = atoi(argv[1]);
            HANDLE hProcess = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE, FALSE, dwProcessId);
            SIZE_T dwBytesRead = 0;
            (void)ReadProcessMemory(hProcess, (LPCVOID)dwTextAddress, lpTextBuffer, sizeof(lpTextBuffer), &dwBytesRead);
            (void)ReadProcessMemory(hProcess, (LPCVOID)dwCaptionAddress, lpTitleBuffer, sizeof(lpTitleBuffer), &dwBytesRead);

            printf("Parameters\n"
                "HWND: %X\n"
                "Text: %s\n"
                "Title: %s\n"
                "Type: %X\n",
                hWnd, lpTextBuffer, lpTitleBuffer, uiType);

            mOutgoingMessage.Clear();
            mOutgoingMessage.set_biscontinue(true);
            (void)SendOutgoingMessage(sckConnect, &mOutgoingMessage);
        } while(!GetAsyncKeyState(VK_F12));

        mOutgoingMessage.Clear();
        mOutgoingMessage.mutable_mremovehook()->set_uihookid(0x123);
        (void)SendOutgoingMessage(sckConnect, &mOutgoingMessage);
    }

    Shutdown(sckConnect);
    google::protobuf::ShutdownProtobufLibrary();

    getchar();

    return 0;
}
