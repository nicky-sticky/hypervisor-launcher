#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <intrin.h>

#include <atomic>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <string>
#include <vector>

#include "ini_parser.hpp"

constexpr DWORD kToolTimeoutMs = 30000;

//  Log
static void logInfo(const std::string& m) { std::cout << "[*] " << m << "\n"; }
static void logOk  (const std::string& m) { std::cout << "[+] " << m << "\n"; }
static void logWarn(const std::string& m) { std::cout << "[!] " << m << "\n"; }
static void logErr (const std::string& m) { std::cout << "[-] " << m << "\n"; }
static void logSec (const std::string& m) { std::cout << "\n[>] " << m << "\n"; }

static void pause() {
    std::cout << "\nPress Enter to exit...";
    std::cin.get();
}

static CpuVendor detectCpu(std::string& vendorOut) {
    int r[4]{};
    __cpuid(r, 0);
    char v[13]{};
    std::memcpy(v + 0, &r[1], 4);
    std::memcpy(v + 4, &r[3], 4);
    std::memcpy(v + 8, &r[2], 4);
    vendorOut = v;
    return classifyCpuVendor(vendorOut);
}

static fs::path exeFilePath() {
    std::vector<wchar_t> buf(MAX_PATH);
    while (true) {
        DWORD len = GetModuleFileNameW(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) {
            logErr("GetModuleFileNameW failed (error " + std::to_string(GetLastError()) + ").");
            return {};
        }
        if (len < buf.size() - 1 || GetLastError() != ERROR_INSUFFICIENT_BUFFER) {
            return fs::path(std::wstring(buf.data(), len));
        }
        if (buf.size() >= 32768) {
            logErr("Executable path exceeded buffer limit.");
            return {};
        }
        buf.resize(buf.size() * 2);
    }
}

static bool isAdmin() {
    BOOL  yes = FALSE;
    PSID  grp = nullptr;
    SID_IDENTIFIER_AUTHORITY ntAuth = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuth, 2, SECURITY_BUILTIN_DOMAIN_RID, DOMAIN_ALIAS_RID_ADMINS, 0,0,0,0,0,0, &grp)) {
        CheckTokenMembership(nullptr, grp, &yes);
        FreeSid(grp);
    }
    return yes == TRUE;
}

static bool runTool(const fs::path& exe, const fs::path& cwd, const std::wstring& args, bool warnOnNonZero = true) {
    if (!fs::exists(exe)) {
        logErr("Tool not found: " + pathToUtf8(exe));
        return false;
    }

    std::wstring wExe      = exe.wstring();
    std::wstring wCwd      = cwd.wstring();
    std::wstring wFilename = exe.filename().wstring();
    std::wstring wArgs     = L"\"" + wFilename + L"\" " + args;

    STARTUPINFOW si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);
    if (!CreateProcessW(wExe.c_str(), wArgs.data(), nullptr, nullptr, FALSE, 0, nullptr, wCwd.c_str(), &si, &pi)) {
        logWarn("CreateProcessW failed for tool (error " + std::to_string(GetLastError()) + ").");
        return false;
    }

    DWORD waitRes = WaitForSingleObject(pi.hProcess, kToolTimeoutMs);
    if (waitRes == WAIT_TIMEOUT) {
        logErr("Tool timed out after 30s; terminating process.");
        TerminateProcess(pi.hProcess, 1);
        WaitForSingleObject(pi.hProcess, 5000);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    if (waitRes == WAIT_FAILED) {
        logErr("WaitForSingleObject failed for tool (error " + std::to_string(GetLastError()) + ").");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        logErr("GetExitCodeProcess failed for tool (error " + std::to_string(GetLastError()) + ").");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);

    if (code != 0 && warnOnNonZero) {
        logWarn("Tool exited with non-zero code " + std::to_string(code) + ".");
    }
    return code == 0;
}

static bool kvcLoadDriver(const fs::path& kvcExe, const fs::path& cwd, const fs::path& driverPath) {
    // Purge any stale driver service registration from previous runs or other targets
    (void)runTool(kvcExe, cwd, formatKvcRemoveArgs(driverPath), false);

    logInfo("kvc driver load \"" + pathToUtf8(driverPath) + "\"");
    if (!runTool(kvcExe, cwd, formatKvcLoadArgs(driverPath)))
        return false;
    logOk("Driver loaded.");
    return true;
}

static bool kvcUnloadDriver(const fs::path& kvcExe, const fs::path& cwd, const fs::path& driverPath) {
    logInfo("kvc driver remove " + pathToUtf8(driverPath.stem()));
    if (!runTool(kvcExe, cwd, formatKvcRemoveArgs(driverPath)))
        return false;
    logOk("Driver unloaded.");
    return true;
}

struct DriverCleanupContext {
    fs::path kvcExe;
    fs::path baseDir;
    fs::path driverPath;
    std::atomic<bool> active{false};
};

static DriverCleanupContext g_cleanupCtx;

static BOOL WINAPI consoleCtrlHandler(DWORD ctrlType) {
    switch (ctrlType) {
        case CTRL_C_EVENT:
        case CTRL_BREAK_EVENT:
        case CTRL_CLOSE_EVENT:
            if (g_cleanupCtx.active.exchange(false)) {
                logWarn("Console interruption detected; attempting best-effort driver unload...");
                (void)kvcUnloadDriver(g_cleanupCtx.kvcExe, g_cleanupCtx.baseDir, g_cleanupCtx.driverPath);
            }
            return FALSE;
        default:
            return FALSE;
    }
}

static bool launchTarget(const fs::path& targetPath) {
    std::wstring wTarget = targetPath.wstring();
    std::wstring cmd = L"\"" + wTarget + L"\"";
    STARTUPINFOW        si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessW(wTarget.c_str(), cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, targetPath.parent_path().wstring().c_str(), &si, &pi)) {
        logErr("CreateProcessW failed (error " + std::to_string(GetLastError()) + ").");
        return false;
    }

    logOk("Target running - PID " + std::to_string(pi.dwProcessId));
    logInfo("Waiting for the target to exit...");
    DWORD waitRes = WaitForSingleObject(pi.hProcess, INFINITE);
    if (waitRes == WAIT_FAILED) {
        logErr("WaitForSingleObject failed for target (error " + std::to_string(GetLastError()) + ").");
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        return false;
    }

    DWORD code = 0;
    if (!GetExitCodeProcess(pi.hProcess, &code)) {
        logWarn("GetExitCodeProcess failed for target (error " + std::to_string(GetLastError()) + ").");
    } else {
        logInfo("Target exited (code " + std::to_string(code) + ").");
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return true;
}

static void banner() {
    std::cout
        << "  +==============================================================+\n"
        << "  |                     Hypervisor Launcher                      |\n"
        << "  +==============================================================+\n";
}

static bool writeDefaultIni(const fs::path& iniPath) {
    std::ofstream f(iniPath);
    if (!f.is_open()) {
        logErr("Failed to write default hvlauncher.ini: " + iniPath.string());
        return false;
    }
    f << buildDefaultIniContent();
    return true;
}

int main() {
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);
    SetConsoleTitleA("Hypervisor Launcher");
    SetConsoleCtrlHandler(consoleCtrlHandler, TRUE);
    banner();

    const fs::path selfExe = exeFilePath();
    if (selfExe.empty()) {
        pause(); return 1;
    }
    const fs::path base    = selfExe.parent_path();
    const fs::path iniPath = base / "hvlauncher.ini";

    if (!isAdmin()) {
        logWarn("Administrator privileges required. Requesting elevation...");
        std::wstring exePathW = selfExe.wstring();
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = exePathW.c_str();
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei)) {
            logErr("Elevation failed (error " + std::to_string(GetLastError()) + "). Please Run as Administrator manually.");
            pause(); return 1;
        }
        if (sei.hProcess) CloseHandle(sei.hProcess);
        return 0;
    }
    logOk("Privileges confirmed.");

    if (!fs::exists(iniPath)) {
        if (writeDefaultIni(iniPath)) {
            logWarn("hvlauncher.ini not found - generated default at:");
            logWarn("  " + pathToUtf8(iniPath));
            logWarn("Please configure [Target] exe= and restart.");
        }
        pause(); return 1;
    }

    IniFile ini;
    if (!ini.load(iniPath)) {
        logErr("Failed to load hvlauncher.ini: " + pathToUtf8(iniPath));
        pause(); return 1;
    }
    logOk("Config loaded: " + pathToUtf8(iniPath));

    std::string targetExeRaw = ini.get("target", "exe",           "");
    std::string amdSys       = ini.get("driver", "amd_sys",       "");
    std::string intelSys     = ini.get("driver", "intel_sys",     "");
    std::string kvcExeRaw    = ini.get("tools", "kvc",            "");

    if (targetExeRaw.empty()) {
        logErr("[Target] exe= is not defined in hvlauncher.ini.");
        pause(); return 1;
    }

    // Driver and kvc locations fall back to the bundled standard layout when unset.
    resolveDriverDefaults(amdSys, intelSys, kvcExeRaw);

    fs::path targetPath = resolvePath(targetExeRaw, base);
    logInfo("Target EXE : " + pathToUtf8(targetPath));

    if (!fs::exists(targetPath)) {
        logErr("Target executable not found.");
        pause(); return 1;
    }

    std::string vendorStr;
    CpuVendor cpu = detectCpu(vendorStr);
    fs::path driverPath;
    std::string cpuLabel;

    switch (cpu) {
        case CpuVendor::AMD:
            cpuLabel   = "AMD (" + vendorStr + ")";
            driverPath = resolvePath(amdSys, base);
            break;
        case CpuVendor::Intel:
            cpuLabel   = "Intel (" + vendorStr + ")";
            driverPath = resolvePath(intelSys, base);
            break;
        default:
            logErr("Unsupported CPU: " + vendorStr);
            pause(); return 1;
    }

    logInfo("CPU detected: " + cpuLabel);
    logInfo("Driver path : " + pathToUtf8(driverPath));

    if (!fs::exists(driverPath)) {
        logErr("Driver file missing: " + pathToUtf8(driverPath));
        pause(); return 1;
    }

    logSec("Loading kernel driver (DSE Bypass)...");
    fs::path kvcExe = resolvePath(kvcExeRaw, base);
    if (!fs::exists(kvcExe)) {
        logErr("kvc executable not found: " + pathToUtf8(kvcExe));
        pause(); return 1;
    }
    if (!kvcLoadDriver(kvcExe, base, driverPath)) {
        logErr("Driver load failed.");
        pause(); return 1;
    }

    g_cleanupCtx.kvcExe = kvcExe;
    g_cleanupCtx.baseDir = base;
    g_cleanupCtx.driverPath = driverPath;
    g_cleanupCtx.active.store(true);

    Sleep(1000);
    logSec("Launching target...");
    bool targetOk = launchTarget(targetPath);

    logSec("Cleaning up...");
    if (g_cleanupCtx.active.exchange(false)) {
        (void)kvcUnloadDriver(kvcExe, base, driverPath);  // best-effort cleanup, non-fatal
    }

    if (!targetOk) {
        logErr("Target did not launch correctly.");
        pause(); return 1;
    }

    logOk("Session complete. Clean exit.");
    Sleep(2000);
    return 0;
}
