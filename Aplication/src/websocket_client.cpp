#include "../include/websocket_client.h"
#include <sstream>
#include <stdexcept>
#include <random>
#include <algorithm>
#include <iostream>

static const char B64_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static std::string b64Encode(const unsigned char* buf, size_t len) {
    std::string out;
    for (size_t i = 0; i < len; i += 3) {
        unsigned char b0 = buf[i];
        unsigned char b1 = (i + 1 < len) ? buf[i + 1] : 0;
        unsigned char b2 = (i + 2 < len) ? buf[i + 2] : 0;
        out += B64_CHARS[b0 >> 2];
        out += B64_CHARS[((b0 & 3) << 4) | (b1 >> 4)];
        out += (i + 1 < len) ? B64_CHARS[((b1 & 0xF) << 2) | (b2 >> 6)] : '=';
        out += (i + 2 < len) ? B64_CHARS[b2 & 63] : '=';
    }
    return out;
}


static void sha1(const unsigned char* msg, size_t msgLen, unsigned char digest[20]) {
    uint32_t h[5] = { 0x67452301u, 0xEFCDAB89u, 0x98BADCFEu, 0x10325476u, 0xC3D2E1F0u };
    std::vector<unsigned char> padded(msg, msg + msgLen);
    padded.push_back(0x80);
    while (padded.size() % 64 != 56) padded.push_back(0);
    uint64_t bitLen = (uint64_t)msgLen * 8;
    for (int i = 7; i >= 0; --i) padded.push_back((unsigned char)(bitLen >> (i * 8)));

    for (size_t i = 0; i < padded.size(); i += 64) {
        uint32_t w[80];
        for (int j = 0; j < 16; j++) {
            w[j] = ((uint32_t)padded[i + j * 4] << 24) | ((uint32_t)padded[i + j * 4 + 1] << 16)
                 | ((uint32_t)padded[i + j * 4 + 2] << 8) | padded[i + j * 4 + 3];
        }
        for (int j = 16; j < 80; j++) {
            uint32_t t = w[j-3] ^ w[j-8] ^ w[j-14] ^ w[j-16];
            w[j] = (t << 1) | (t >> 31);
        }
        uint32_t a = h[0], b = h[1], c = h[2], d = h[3], e = h[4];
        for (int j = 0; j < 80; j++) {
            uint32_t f, k;
            if      (j < 20) { f = (b & c) | (~b & d); k = 0x5A827999u; }
            else if (j < 40) { f = b ^ c ^ d;           k = 0x6ED9EBA1u; }
            else if (j < 60) { f = (b & c) | (b & d) | (c & d); k = 0x8F1BBCDCu; }
            else             { f = b ^ c ^ d;           k = 0xCA62C1D6u; }
            uint32_t temp = ((a << 5) | (a >> 27)) + f + e + k + w[j];
            e = d; d = c; c = (b << 30) | (b >> 2); b = a; a = temp;
        }
        h[0] += a; h[1] += b; h[2] += c; h[3] += d; h[4] += e;
    }
    for (int i = 0; i < 5; i++) {
        digest[i * 4 + 0] = (h[i] >> 24) & 0xFF;
        digest[i * 4 + 1] = (h[i] >> 16) & 0xFF;
        digest[i * 4 + 2] = (h[i] >>  8) & 0xFF;
        digest[i * 4 + 3] =  h[i]        & 0xFF;
    }
}

WebSocketClient::WebSocketClient() {
    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
}

WebSocketClient::~WebSocketClient() {
    disconnect();
    WSACleanup();
}

bool WebSocketClient::connect(const std::string& host, int port, const std::string& path) {
    struct addrinfo hints{}, *res = nullptr;
    hints.ai_family   = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &res) != 0)
        return false;

    m_socket = socket(res->ai_family, res->ai_socktype, res->ai_protocol);
    if (m_socket == INVALID_SOCKET) { freeaddrinfo(res); return false; }

    if (::connect(m_socket, res->ai_addr, (int)res->ai_addrlen) != 0) {
        freeaddrinfo(res); closesocket(m_socket); m_socket = INVALID_SOCKET; return false;
    }
    freeaddrinfo(res);

    if (!performHandshake(host, path)) {
        closesocket(m_socket); m_socket = INVALID_SOCKET; return false;
    }

    m_connected = true;
    m_recvThread = std::thread(&WebSocketClient::recvLoop, this);
    return true;
}

void WebSocketClient::disconnect() {
    m_connected = false;
    if (m_socket != INVALID_SOCKET) {
        closesocket(m_socket);
        m_socket = INVALID_SOCKET;
    }
    if (m_recvThread.joinable()) m_recvThread.join();
}

bool WebSocketClient::isConnected() const { return m_connected; }

std::string WebSocketClient::generateKey() {
    unsigned char buf[16];
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : buf) b = (unsigned char)dist(rng);
    return b64Encode(buf, 16);
}

bool WebSocketClient::performHandshake(const std::string& host, const std::string& path) {
    std::string req = buildHandshakeRequest(host, path);
    if (::send(m_socket, req.c_str(), (int)req.size(), 0) == SOCKET_ERROR) return false;

    std::string response;
    char buf[1];
    while (true) {
        int r = recv(m_socket, buf, 1, 0);
        if (r <= 0) return false;
        response += buf[0];
        if (response.size() >= 4 && response.substr(response.size() - 4) == "\r\n\r\n") break;
    }
    return response.find("101") != std::string::npos;
}

std::string WebSocketClient::buildHandshakeRequest(const std::string& host, const std::string& path) {
    std::string key = generateKey();
    std::ostringstream ss;
    ss << "GET " << path << " HTTP/1.1\r\n"
       << "Host: " << host << "\r\n"
       << "Upgrade: websocket\r\n"
       << "Connection: Upgrade\r\n"
       << "Sec-WebSocket-Key: " << key << "\r\n"
       << "Sec-WebSocket-Version: 13\r\n"
       << "\r\n";
    return ss.str();
}

bool WebSocketClient::send(const std::string& message) {
    std::lock_guard<std::mutex> lock(m_sendMutex);
    return sendFrame(message);
}

bool WebSocketClient::sendFrame(const std::string& payload) {
    if (m_socket == INVALID_SOCKET) return false;

    std::vector<unsigned char> frame;
    frame.push_back(0x81);

    size_t len = payload.size();
    if (len <= 125) {
        frame.push_back((unsigned char)(0x80 | len));
    } else if (len <= 65535) {
        frame.push_back(0x80 | 126);
        frame.push_back((len >> 8) & 0xFF);
        frame.push_back(len & 0xFF);
    } else {
        frame.push_back(0x80 | 127);
        for (int i = 7; i >= 0; --i) frame.push_back((len >> (i * 8)) & 0xFF);
    }

    unsigned char mask[4];
    std::mt19937 rng(std::random_device{}());
    std::uniform_int_distribution<int> dist(0, 255);
    for (auto& b : mask) { b = (unsigned char)dist(rng); frame.push_back(b); }

    for (size_t i = 0; i < len; ++i)
        frame.push_back((unsigned char)payload[i] ^ mask[i % 4]);

    int sent = ::send(m_socket, (const char*)frame.data(), (int)frame.size(), 0);
    return sent != SOCKET_ERROR;
}

void WebSocketClient::recvLoop() {
    while (m_connected) {
        std::string msg = readFrame();
        if (msg.empty() && !m_connected) break;
        if (!msg.empty() && m_onMessage) m_onMessage(msg);
    }
    if (m_onClose) m_onClose();
}

std::string WebSocketClient::readFrame() {
    auto recvByte = [&]() -> int {
        unsigned char b;
        int r = recv(m_socket, (char*)&b, 1, 0);
        if (r <= 0) { m_connected = false; return -1; }
        return b;
    };

    int b0 = recvByte(); if (b0 < 0) return "";
    int b1 = recvByte(); if (b1 < 0) return "";

    int  opcode = b0 & 0x0F;
    bool masked = (b1 & 0x80) != 0;
    size_t len  = b1 & 0x7F;

    if (len == 126) {
        int h = recvByte(), l = recvByte();
        if (h < 0 || l < 0) return "";
        len = ((size_t)h << 8) | (size_t)l;
    } else if (len == 127) {
        len = 0;
        for (int i = 0; i < 8; ++i) {
            int b = recvByte(); if (b < 0) return "";
            len = (len << 8) | (size_t)b;
        }
    }

    unsigned char maskKey[4] = {};
    if (masked) {
        for (int i = 0; i < 4; ++i) {
            int b = recvByte(); if (b < 0) return "";
            maskKey[i] = (unsigned char)b;
        }
    }

    std::string payload(len, '\0');
    size_t received = 0;
    while (received < len) {
        int r = recv(m_socket, &payload[received], (int)(len - received), 0);
        if (r <= 0) { m_connected = false; return ""; }
        received += r;
    }

    if (masked)
        for (size_t i = 0; i < len; ++i)
            payload[i] ^= maskKey[i % 4];

    if (opcode == 0x8) { m_connected = false; return ""; }

    return payload;
}

