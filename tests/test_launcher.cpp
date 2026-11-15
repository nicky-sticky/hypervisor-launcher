#include "../source/ini_parser.hpp"

#include <cstdlib>
#include <fstream>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

namespace {

int g_failures = 0;

void check(bool condition, const char* expr, int line) {
    if (!condition) {
        std::cerr << "FAIL [line " << line << "]: " << expr << "\n";
        ++g_failures;
    }
}

#define EXPECT_TRUE(cond) check(static_cast<bool>(cond), #cond, __LINE__)
#define EXPECT_EQ(a, b) check((a) == (b), #a " == " #b, __LINE__)

fs::path createTempDir(const std::wstring& suffix) {
    fs::path dir = fs::temp_directory_path() / (L"hvlauncher_tests_" + suffix);
    std::error_code ec;
    fs::remove_all(dir, ec);
    fs::create_directories(dir, ec);
    return dir;
}

void testUtf8WideRoundtrip() {
    EXPECT_EQ(utf8ToWide(""), L"");
    EXPECT_EQ(wideToUtf8(L""), "");

    std::string ascii = "C:\\Games\\Sample\\game.exe";
    std::wstring wideAscii = utf8ToWide(ascii);
    EXPECT_EQ(wideAscii, L"C:\\Games\\Sample\\game.exe");
    EXPECT_EQ(wideToUtf8(wideAscii), ascii);

    // UTF-8 multi-byte characters (Japanese + accented Latin)
    std::string utf8Multi = "C:\\Games\\\xE6\x97\xA5\xE6\x9C\xAC\xE8\xAA\x9E\\Caf\xC3\xA9.exe";
    std::wstring wideMulti = utf8ToWide(utf8Multi);
    EXPECT_TRUE(!wideMulti.empty());
    EXPECT_EQ(wideToUtf8(wideMulti), utf8Multi);
    EXPECT_EQ(pathToUtf8(fs::path(wideMulti)), utf8Multi);
}

void testIniSectionsAndComments() {
    const std::string raw =
        "; leading comment\n"
        "# hash comment\n"
        "orphan_key = orphan_val\n"
        "\n"
        "[ Target ]\r\n"
        "EXE = \"C:\\Games\\My ; Game #1\\app.exe\" ; trailing comment\r\n"
        "Args = --windowed # hash inline\n"
        "SingleQuoted = 'semi;colon#inside' # comment outside\n"
        "MalformedLineWithoutEquals\n"
        "EmptyVal =\n"
        "[DRIVER]\n"
        "AMD_SYS = driver_amd\\SimpleSvm.sys\n"
        "amd_sys = override_amd\\Custom.sys\n";

    std::istringstream iss(raw);
    IniFile ini;
    EXPECT_TRUE(ini.parse(iss));

    EXPECT_EQ(ini.get("default", "orphan_key"), "orphan_val");
    EXPECT_EQ(ini.get("target", "exe"), "C:\\Games\\My ; Game #1\\app.exe");
    EXPECT_EQ(ini.get("target", "args"), "--windowed");
    EXPECT_EQ(ini.get("target", "singlequoted"), "semi;colon#inside");
    EXPECT_EQ(ini.get("target", "emptyval", "fallback"), "");
    EXPECT_EQ(ini.get("target", "missing_key", "fallback"), "fallback");
    EXPECT_EQ(ini.get("missing_section", "exe", "none"), "none");
    EXPECT_EQ(ini.get("driver", "amd_sys"), "override_amd\\Custom.sys");
}

void testIniUtf8BomAndLoad() {
    fs::path tempDir = createTempDir(L"bom");

    IniFile missingIni;
    EXPECT_TRUE(!missingIni.load(tempDir / "does_not_exist.ini"));

    // File starting with UTF-8 BOM (EF BB BF)
    fs::path bomFile = tempDir / "bom.ini";
    {
        std::ofstream out(bomFile, std::ios::binary);
        const unsigned char bom[3] = {0xEF, 0xBB, 0xBF};
        out.write(reinterpret_cast<const char*>(bom), 3);
        out << "[Target]\nexe = bom_target.exe\n";
    }
    IniFile bomIni;
    EXPECT_TRUE(bomIni.load(bomFile));
    EXPECT_EQ(bomIni.get("target", "exe"), "bom_target.exe");

    // Default INI generation roundtrip
    fs::path defFile = tempDir / "default.ini";
    {
        std::ofstream out(defFile, std::ios::binary);
        out << buildDefaultIniContent();
    }
    IniFile defIni;
    EXPECT_TRUE(defIni.load(defFile));
    EXPECT_EQ(defIni.get("target", "exe"), "target.exe");
    EXPECT_EQ(defIni.get("driver", "amd_sys"), "driver_amd\\SimpleSvm.sys");
    EXPECT_EQ(defIni.get("driver", "intel_sys"), "driver_intel\\hyperkd.sys");
    EXPECT_EQ(defIni.get("tools", "kvc"), "tools\\kvc.exe");

    // Non-BOM stream starting with a non-BOM 0xEF byte must rewind cleanly
    std::string nonBom = "\xEF" "key = value\n";
    std::istringstream nonBomStream(nonBom);
    IniFile nonBomIni;
    EXPECT_TRUE(nonBomIni.parse(nonBomStream));
    EXPECT_EQ(nonBomIni.data["default"].size(), size_t(1));

    std::error_code ec;
    fs::remove_all(tempDir, ec);
}

void testResolvePathAndHelpers() {
    fs::path base(L"C:\\BaseDir");

    EXPECT_EQ(resolvePath("bin\\game.exe", base), fs::path(L"C:\\BaseDir\\bin\\game.exe"));
    EXPECT_EQ(resolvePath("\"sub\\game.exe\"", base), fs::path(L"C:\\BaseDir\\sub\\game.exe"));
    EXPECT_EQ(resolvePath("'C:\\Abs\\app.exe'", base), fs::path(L"C:\\Abs\\app.exe"));
    EXPECT_EQ(resolvePath("\"D:\\Games\\App.exe\"", base), fs::path(L"D:\\Games\\App.exe"));

    EXPECT_TRUE(classifyCpuVendor("AuthenticAMD") == CpuVendor::AMD);
    EXPECT_TRUE(classifyCpuVendor("GenuineIntel") == CpuVendor::Intel);
    EXPECT_TRUE(classifyCpuVendor("UnknownVendor") == CpuVendor::Unknown);
    EXPECT_TRUE(classifyCpuVendor("") == CpuVendor::Unknown);

    std::string amd, intel, kvc;
    resolveDriverDefaults(amd, intel, kvc);
    EXPECT_EQ(amd, "driver_amd\\SimpleSvm.sys");
    EXPECT_EQ(intel, "driver_intel\\hyperkd.sys");
    EXPECT_EQ(kvc, "tools\\kvc.exe");

    std::string customAmd = "custom.sys";
    std::string emptyIntel;
    std::string customKvc = "bin\\kvc2.exe";
    resolveDriverDefaults(customAmd, emptyIntel, customKvc);
    EXPECT_EQ(customAmd, "custom.sys");
    EXPECT_EQ(emptyIntel, "driver_intel\\hyperkd.sys");
    EXPECT_EQ(customKvc, "bin\\kvc2.exe");

    fs::path driver(L"C:\\BaseDir\\driver_amd\\SimpleSvm.sys");
    EXPECT_EQ(formatKvcRemoveArgs(driver), std::wstring(L"driver remove SimpleSvm"));
    EXPECT_EQ(formatKvcLoadArgs(driver), std::wstring(L"driver load \"C:\\BaseDir\\driver_amd\\SimpleSvm.sys\""));
}

}  // namespace

int main() {
    testUtf8WideRoundtrip();
    testIniSectionsAndComments();
    testIniUtf8BomAndLoad();
    testResolvePathAndHelpers();

    if (g_failures > 0) {
        std::cerr << g_failures << " check(s) failed.\n";
        return 1;
    }
    std::cout << "[+] All C++ launcher unit tests passed.\n";
    return 0;
}
