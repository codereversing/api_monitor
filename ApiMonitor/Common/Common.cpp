#include "Common.h"

const bool Send(SOCKET sckConnect, const char *pBuffer, int uiBufferLength)
{
    int iResult = send(sckConnect, (const char *)pBuffer, uiBufferLength, 0);
    if (iResult == SOCKET_ERROR)
    {
        printf("send failed. Error = %X\n", WSAGetLastError());
        closesocket(sckConnect);
        WSACleanup();
        return false;
    }

    return true;
}

const bool SendOutgoingMessage(SOCKET sckConnect, ApiMonitor::ProtoBuf::MonitorMessage *pMessage)
{
    const int iBuffSize = pMessage->ByteSize();

    char *pBuffer = (char *)malloc(iBuffSize * sizeof(char));
    pMessage->SerializePartialToArray(pBuffer, iBuffSize);

    bool bRet = Send(sckConnect, (const char *)&iBuffSize, sizeof(int));
    bRet &= Send(sckConnect, pBuffer, iBuffSize);

    free(pBuffer);

    return bRet;
}