#pragma once

#define WIN32_LEAN_AND_MEAN
#include <windows.h>

#include <algorithm>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <istream>
#include <map>
#include <string>

namespace fs = std::filesystem;

inline std::wstring utf8ToWide(const std::string& str) {
    if (str.empty()) return {};
    int needed = MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, str.data(), static_cast<int>(str.size()), nullptr, 0);
    UINT cp = CP_UTF8;
    DWORD flags = MB_ERR_INVALID_CHARS;
    if (needed <= 0) {
        cp = CP_ACP;
        flags = 0;
        needed = MultiByteToWideChar(cp, flags, str.data(), static_cast<int>(str.size()), nullptr, 0);
        if (needed <= 0) return {};
    }
    std::wstring out(static_cast<size_t>(needed), L'\0');
    MultiByteToWideChar(cp, flags, str.data(), static_cast<int>(str.size()), out.data(), needed);
    return out;
}

inline std::string wideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return {};
    int needed = WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), nullptr, 0, nullptr, nullptr);
    if (needed <= 0) return {};
    std::string out(static_cast<size_t>(needed), '\0');
    WideCharToMultiByte(CP_UTF8, 0, wstr.data(), static_cast<int>(wstr.size()), out.data(), needed, nullptr, nullptr);
    return out;
}

inline std::string pathToUtf8(const fs::path& p) {
    return wideToUtf8(p.wstring());
}

class IniFile {
public:
    using SectionMap = std::map<std::string, std::string>;
    std::map<std::string, SectionMap> data;

    bool parse(std::istream& f) {
        data.clear();

        // Strip UTF-8 BOM (0xEF 0xBB 0xBF)
        if (f.peek() == 0xEF) {
            char bom[3];
            f.read(bom, 3);
            if (!f || (unsigned char)bom[0] != 0xEF || (unsigned char)bom[1] != 0xBB || (unsigned char)bom[2] != 0xBF) {
                f.clear();
                f.seekg(0);  // not a real BOM — rewind
            }
        }

        std::string line, section = "default";
        while (std::getline(f, line)) {
            trim(line);
            if (line.empty() || line[0] == '#' || line[0] == ';') continue;

            if (line.front() == '[' && line.back() == ']') {
                section = line.substr(1, line.size() - 2);
                trim(section);
                toLower(section);
                continue;
            }

            auto eq = line.find('=');
            if (eq == std::string::npos) continue;

            std::string key = line.substr(0, eq);
            std::string val = line.substr(eq + 1);
            trim(key);
            trim(val);
            toLower(key);

            char activeQuote = '\0';
            for (size_t i = 0; i < val.size(); ++i) {
                char c = val[i];
                if (activeQuote != '\0') {
                    if (c == activeQuote) activeQuote = '\0';
                } else if (c == '"' || c == '\'') {
                    activeQuote = c;
                } else if (c == ';' || c == '#') {
                    val = val.substr(0, i);
                    break;
                }
            }
            trim(val);
            if (val.size() >= 2 &&
                ((val.front() == '"' && val.back() == '"') ||
                 (val.front() == '\'' && val.back() == '\''))) {
                val = val.substr(1, val.size() - 2);
                trim(val);
            }

            data[section][key] = val;
        }
        return true;
    }

    bool load(const fs::path& path) {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return false;
        return parse(f);
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
        auto first = s.find_first_not_of(ws);
        if (first == std::string::npos) {
            s.clear();
            return;
        }
        s.erase(0, first);
        auto e = s.find_last_not_of(ws);
        if (e != std::string::npos) s.erase(e + 1);
        else s.clear();
    }

    static void toLower(std::string& s) {
        std::transform(s.begin(), s.end(), s.begin(),
            [](unsigned char c) { return (char)std::tolower(c); });
    }
};

enum class CpuVendor { AMD, Intel, Unknown };

inline CpuVendor classifyCpuVendor(const std::string& vendor) {
    if (vendor == "AuthenticAMD") return CpuVendor::AMD;
    if (vendor == "GenuineIntel") return CpuVendor::Intel;
    return CpuVendor::Unknown;
}

inline std::wstring formatKvcRemoveArgs(const fs::path& driverPath) {
    return L"driver remove " + driverPath.stem().wstring();
}

inline std::wstring formatKvcLoadArgs(const fs::path& driverPath) {
    return L"driver load \"" + driverPath.wstring() + L"\"";
}

inline void resolveDriverDefaults(std::string& amdSys, std::string& intelSys, std::string& kvcExeRaw) {
    if (amdSys.empty())    amdSys    = "driver_amd\\SimpleSvm.sys";
    if (intelSys.empty())  intelSys  = "driver_intel\\hyperkd.sys";
    if (kvcExeRaw.empty()) kvcExeRaw = "tools\\kvc.exe";
}

inline std::string buildDefaultIniContent() {
    return "[Target]\n"
           "; Target executable (absolute, or relative to the launcher directory)\n"
           "exe = target.exe\n"
           "\n"
           "[Driver]\n"
           "; Driver .sys paths (absolute, or relative to the launcher directory).\n"
           "; When a key is omitted or empty, the bundled layout default is used.\n"
           "amd_sys   = driver_amd\\SimpleSvm.sys\n"
           "intel_sys = driver_intel\\hyperkd.sys\n"
           "\n"
           "[Tools]\n"
           "; kvc engine executable (absolute, or relative to the launcher directory).\n"
           "; When the key is omitted or empty, the bundled layout default tools\\kvc.exe is used.\n"
           "kvc = tools\\kvc.exe\n";
}

inline fs::path resolvePath(const std::string& raw, const fs::path& base) {
    std::string cleaned = raw;
    if (cleaned.size() >= 2 &&
        ((cleaned.front() == '"' && cleaned.back() == '"') ||
         (cleaned.front() == '\'' && cleaned.back() == '\''))) {
        cleaned = cleaned.substr(1, cleaned.size() - 2);
    }
    fs::path p(utf8ToWide(cleaned));
    if (p.is_absolute()) return p;
    return base / p;
}
