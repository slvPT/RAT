#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>

#include <string>
#include <functional>
#include <thread>
#include <atomic>
#include <vector>
#include <mutex>

#pragma comment(lib, "ws2_32.lib")

class WebSocketClient {
public:
    using MessageCallback = std::function<void(const std::string&)>;
    using CloseCallback   = std::function<void()>;

    WebSocketClient();
    ~WebSocketClient();

    bool connect(const std::string& host, int port, const std::string& path = "/");
    void disconnect();
    bool send(const std::string& message);
    bool isConnected() const;

    void onMessage(MessageCallback cb) { m_onMessage = cb; }
    void onClose(CloseCallback cb)     { m_onClose   = cb; }

private:
    SOCKET            m_socket = INVALID_SOCKET;
    std::atomic<bool> m_connected{ false };
    std::thread       m_recvThread;
    MessageCallback   m_onMessage;
    CloseCallback     m_onClose;
    std::mutex        m_sendMutex;

    bool        performHandshake(const std::string& host, const std::string& path);
    std::string buildHandshakeRequest(const std::string& host, const std::string& path);
    std::string generateKey();
    void        recvLoop();
    bool        sendFrame(const std::string& payload);
    std::string readFrame();
};

