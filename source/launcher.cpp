#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <shellapi.h>
#include <intrin.h>

#include <algorithm>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <map>
#include <string>

namespace fs = std::filesystem;

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

class IniFile {
public:
    using SectionMap = std::map<std::string, std::string>;
    std::map<std::string, SectionMap> data;

    bool load(const fs::path& path) {
        std::ifstream f(path);
        if (!f.is_open()) return false;

        // Strip UTF-8 BOM (0xEF 0xBB 0xBF)
        if (f.peek() == 0xEF) {
            char bom[3];
            f.read(bom, 3);
            if ((unsigned char)bom[0] != 0xEF || (unsigned char)bom[1] != 0xBB || (unsigned char)bom[2] != 0xBF)
                f.seekg(0);  // not a real BOM — rewind
        }

        std::string line, section = "default";
        while (std::getline(f, line)) {
            trim(line);
            if (line.empty() || line[0]=='#' || line[0]==';') continue;

            if (line.front()=='[' && line.back()==']') {
                section = line.substr(1, line.size()-2);
                trim(section);
                toLower(section);
                continue;
            }

            auto eq = line.find('=');
            if (eq == std::string::npos) continue;

            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            trim(key); trim(val);
            toLower(key);

            auto sc = val.find(';');
            if (sc != std::string::npos) val = val.substr(0, sc);
            auto hsh = val.find('#');
            if (hsh != std::string::npos) val = val.substr(0, hsh);
            trim(val);

            data[section][key] = val;
        }
        return true;
    }

    std::string get(const std::string& sec, const std::string& key, const std::string& def = "") const {
        auto s = data.find(sec);
        if (s == data.end()) return def;
        auto k = s->second.find(key);
        if (k == s->second.end()) return def;
        return k->second;
    }

private:
    static void trim(std::string& s) {
        const char* ws = " \t\r\n";
        s.erase(0, s.find_first_not_of(ws));
        auto e = s.find_last_not_of(ws);
        if (e != std::string::npos) s.erase(e+1);
        else s.clear();
    }
    static void toLower(std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return (char)std::tolower(c); });
    }
};

//  CPU detection
enum class CpuVendor { AMD, Intel, Unknown };

static CpuVendor detectCpu(std::string& vendorOut) {
    int r[4]{};
    __cpuid(r, 0);
    char v[13]{};
    std::memcpy(v + 0, &r[1], 4);
    std::memcpy(v + 4, &r[3], 4);
    std::memcpy(v + 8, &r[2], 4);
    vendorOut = v;
    if (vendorOut == "AuthenticAMD") return CpuVendor::AMD;
    if (vendorOut == "GenuineIntel") return CpuVendor::Intel;
    return CpuVendor::Unknown;
}

static fs::path exeDir() {
    wchar_t buf[MAX_PATH]{};
    GetModuleFileNameW(nullptr, buf, MAX_PATH);
    return fs::path(buf).parent_path();
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

static bool runTool(const fs::path& exe, const fs::path& cwd, const std::wstring& args) {
    if (!fs::exists(exe)) {
        logErr("Tool not found: " + exe.string());
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
        logWarn("CreateProcess failed for tool.");
        return false;
    }
    WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return code == 0;
}

static bool kvcLoadDriver(const fs::path& kvcExe, const fs::path& cwd, const fs::path& driverPath) {
    // Purge any stale driver service registration from previous runs or other targets
    (void)runTool(kvcExe, cwd, L"driver remove " + driverPath.stem().wstring());

    logInfo("kvc driver load \"" + driverPath.string() + "\"");
    if (!runTool(kvcExe, cwd, L"driver load \"" + driverPath.wstring() + L"\""))
        return false;
    logOk("Driver loaded.");
    return true;
}

static bool kvcUnloadDriver(const fs::path& kvcExe, const fs::path& cwd, const fs::path& driverPath) {
    logInfo("kvc driver remove " + driverPath.stem().string());
    if (!runTool(kvcExe, cwd, L"driver remove " + driverPath.stem().wstring()))
        return false;
    logOk("Driver unloaded.");
    return true;
}

static bool launchTarget(const fs::path& targetPath) {
    std::wstring cmd = L"\"" + targetPath.wstring() + L"\"";
    STARTUPINFOW        si{};
    PROCESS_INFORMATION pi{};
    si.cb = sizeof(si);

    if (!CreateProcessW(targetPath.wstring().c_str(), cmd.data(), nullptr, nullptr, FALSE, 0, nullptr, targetPath.parent_path().wstring().c_str(), &si, &pi)) {
        logErr("CreateProcess failed.");
        return false;
    }

    logOk("Target running - PID " + std::to_string(pi.dwProcessId));
    logInfo("Waiting for the target to exit...");
    WaitForSingleObject(pi.hProcess, INFINITE);

    DWORD code = 0;
    GetExitCodeProcess(pi.hProcess, &code);
    logInfo("Target exited (code " + std::to_string(code) + ").");

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
    f << "[Target]\n"
      << "; Target executable (absolute, or relative to the launcher directory)\n"
      << "exe = target.exe\n"
      << "\n"
      << "[Driver]\n"
      << "; Driver .sys paths (absolute, or relative to the launcher directory).\n"
      << "; When a key is omitted or empty, the bundled layout default is used.\n"
      << "amd_sys   = driver_amd\\SimpleSvm.sys\n"
      << "intel_sys = driver_intel\\hyperkd.sys\n"
      << "\n"
      << "[Tools]\n"
      << "; kvc engine executable (absolute, or relative to the launcher directory).\n"
      << "; When the key is omitted or empty, the bundled layout default tools\\kvc.exe is used.\n"
      << "kvc = tools\\kvc.exe\n";
    return true;
}

static fs::path resolvePath(const std::string& raw, const fs::path& base) {
    fs::path p(raw);
    if (p.is_absolute()) return p;
    return base / p;
}

int main() {
    SetConsoleTitleA("Hypervisor Launcher");
    banner();

    const fs::path base    = exeDir();
    const fs::path iniPath = base / "hvlauncher.ini";

    if (!isAdmin()) {
        logWarn("Administrator privileges required. Requesting elevation...");
        wchar_t exePath[MAX_PATH]{};
        GetModuleFileNameW(nullptr, exePath, MAX_PATH);
        SHELLEXECUTEINFOW sei = { sizeof(sei) };
        sei.fMask = SEE_MASK_NOCLOSEPROCESS;
        sei.lpVerb = L"runas";
        sei.lpFile = exePath;
        sei.nShow = SW_NORMAL;
        if (!ShellExecuteExW(&sei)) {
            logErr("Elevation failed. Please Run as Administrator manually.");
            pause(); return 1;
        }
        CloseHandle(sei.hProcess);
        return 0;
    }
    logOk("Privileges confirmed.");

    if (!fs::exists(iniPath)) {
        if (writeDefaultIni(iniPath)) {
            logWarn("hvlauncher.ini not found - generated default at:");
            logWarn("  " + iniPath.string());
            logWarn("Please configure [Target] exe= and restart.");
        }
        pause(); return 1;
    }

    IniFile ini;
    if (!ini.load(iniPath)) {
        logErr("Failed to load hvlauncher.ini: " + iniPath.string());
        pause(); return 1;
    }
    logOk("Config loaded: " + iniPath.string());

    std::string targetExeRaw = ini.get("target", "exe",           "");
    std::string amdSys       = ini.get("driver", "amd_sys",       "");
    std::string intelSys     = ini.get("driver", "intel_sys",     "");
    std::string kvcExeRaw    = ini.get("tools", "kvc",            "");

    if (targetExeRaw.empty()) {
        logErr("[Target] exe= is not defined in hvlauncher.ini.");
        pause(); return 1;
    }

    // Driver and kvc locations fall back to the bundled standard layout when unset.
    if (amdSys.empty())      amdSys    = "driver_amd\\SimpleSvm.sys";
    if (intelSys.empty())    intelSys  = "driver_intel\\hyperkd.sys";
    if (kvcExeRaw.empty())   kvcExeRaw = "tools\\kvc.exe";

    fs::path targetPath = resolvePath(targetExeRaw, base);
    logInfo("Target EXE : " + targetPath.string());

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
    logInfo("Driver path : " + driverPath.string());

    if (!fs::exists(driverPath)) {
        logErr("Driver file missing: " + driverPath.string());
        pause(); return 1;
    }

    logSec("Loading kernel driver (DSE Bypass)...");
    fs::path kvcExe = resolvePath(kvcExeRaw, base);
    if (!fs::exists(kvcExe)) {
        logErr("kvc executable not found: " + kvcExe.string());
        pause(); return 1;
    }
    if (!kvcLoadDriver(kvcExe, base, driverPath)) {
        logErr("Driver load failed.");
        pause(); return 1;
    }

    Sleep(1000);
    logSec("Launching target...");
    bool targetOk = launchTarget(targetPath);

    logSec("Cleaning up...");
    (void)kvcUnloadDriver(kvcExe, base, driverPath);  // best-effort cleanup, non-fatal

    if (!targetOk) {
        logErr("Target did not launch correctly.");
        pause(); return 1;
    }

    logOk("Session complete. Clean exit.");
    Sleep(2000);
    return 0;
}
