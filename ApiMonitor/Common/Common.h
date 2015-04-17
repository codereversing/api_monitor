#pragma once

#include <stdio.h>

#include <Windows.h>

#include "monitor.pb.h"

const bool Send(SOCKET sckConnect, const char *pBuffer, int uiBufferLength);
const bool SendOutgoingMessage(SOCKET sckConnect, ApiMonitor::ProtoBuf::MonitorMessage *pMessage);