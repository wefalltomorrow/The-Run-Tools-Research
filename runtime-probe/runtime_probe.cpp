#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>

static constexpr uintptr_t kGameCurrentLevel = 0x0289BDC8;
static constexpr uintptr_t kGameSecondaryLevel = 0x0289BCC8;
static constexpr uintptr_t kLevelObjectGlobal = 0x02888F80;

static const char* kDesertHills = "_c4/Levels/Level_0500_DesertHills/Level_0500_DesertHills";
static const char* kBuffaloGap  = "_c4/Levels/Level_2300_BuffaloGap/Level_2300_BuffaloGap";

static FILE* gLog = nullptr;
static std::mutex gLogMutex;
static std::vector<uintptr_t> gPatched;
static volatile bool gRunning = true;

static void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(gLogMutex);
    if (!gLog) return;
    SYSTEMTIME st{};
    GetLocalTime(&st);
    std::fprintf(gLog, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args;
    va_start(args, fmt);
    std::vfprintf(gLog, fmt, args);
    va_end(args);
    std::fputc('\n', gLog);
    std::fflush(gLog);
}

static bool IsReadableProtect(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWritableProtect(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static std::string SafeCString(uintptr_t address, size_t maxLen = 260)
{
    if (!address) return "<null>";
    __try {
        const char* s = reinterpret_cast<const char*>(address);
        size_t n = 0;
        while (n < maxLen && s[n]) ++n;
        if (n == maxLen) return "<unterminated/unreadable>";
        return std::string(s, n);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        return "<unreadable>";
    }
}

static void DumpState()
{
    Log("---- STATE DUMP ----");
    Log("global current  [0x%08X] = %s", (unsigned)kGameCurrentLevel,
        SafeCString(kGameCurrentLevel).c_str());
    Log("global secondary[0x%08X] = %s", (unsigned)kGameSecondaryLevel,
        SafeCString(kGameSecondaryLevel).c_str());

    __try {
        uintptr_t obj = *reinterpret_cast<uintptr_t*>(kLevelObjectGlobal);
        Log("level object global [0x%08X] -> 0x%08X", (unsigned)kLevelObjectGlobal, (unsigned)obj);
        if (obj) {
            uintptr_t p = *reinterpret_cast<uintptr_t*>(obj + 0x9C);
            Log("level object +0x9C -> 0x%08X = %s", (unsigned)p, SafeCString(p).c_str());
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        Log("level object read failed");
    }
}

static std::vector<uintptr_t> FindWritableCString(const char* needle)
{
    std::vector<uintptr_t> hits;
    const size_t needleLen = std::strlen(needle);
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t p = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t end = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi))) break;
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const size_t size = mbi.RegionSize;

        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && IsWritableProtect(mbi.Protect) && size > needleLen) {
            __try {
                const unsigned char* data = reinterpret_cast<const unsigned char*>(base);
                for (size_t i = 0; i + needleLen < size; ++i) {
                    if (data[i] == static_cast<unsigned char>(needle[0]) &&
                        std::memcmp(data + i, needle, needleLen) == 0 && data[i + needleLen] == 0) {
                        hits.push_back(base + i);
                        i += needleLen;
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {
                // Region changed or became inaccessible; skip it.
            }
        }

        if (base + size <= p) break;
        p = base + size;
    }
    return hits;
}

static void DumpPointerRefs(uintptr_t target)
{
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    uintptr_t p = reinterpret_cast<uintptr_t>(si.lpMinimumApplicationAddress);
    const uintptr_t end = reinterpret_cast<uintptr_t>(si.lpMaximumApplicationAddress);
    unsigned count = 0;

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery(reinterpret_cast<LPCVOID>(p), &mbi, sizeof(mbi))) break;
        const uintptr_t base = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
        const size_t size = mbi.RegionSize;
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && IsReadableProtect(mbi.Protect) && size >= sizeof(uint32_t)) {
            __try {
                const uint32_t* q = reinterpret_cast<const uint32_t*>(base);
                const size_t n = size / sizeof(uint32_t);
                for (size_t i = 0; i < n; ++i) {
                    if (q[i] == static_cast<uint32_t>(target)) {
                        uintptr_t at = base + i * 4;
                        Log("    ptrref 0x%08X -> 0x%08X", (unsigned)at, (unsigned)target);
                        ++count;
                        if (count >= 64) {
                            Log("    ptrref limit reached (64)");
                            return;
                        }
                    }
                }
            }
            __except (EXCEPTION_EXECUTE_HANDLER) {}
        }
        if (base + size <= p) break;
        p = base + size;
    }
    Log("    pointer refs found: %u", count);
}

static void ScanDesertHills(bool withRefs)
{
    auto hits = FindWritableCString(kDesertHills);
    Log("---- DESERT HILLS LIVE SCAN: %zu writable private/mapped exact string(s) ----", hits.size());
    for (size_t i = 0; i < hits.size(); ++i) {
        MEMORY_BASIC_INFORMATION mbi{};
        VirtualQuery(reinterpret_cast<LPCVOID>(hits[i]), &mbi, sizeof(mbi));
        Log("  hit[%zu] 0x%08X regionBase=0x%08X size=0x%zX type=0x%lX protect=0x%lX",
            i, (unsigned)hits[i], (unsigned)(uintptr_t)mbi.BaseAddress, mbi.RegionSize,
            (unsigned long)mbi.Type, (unsigned long)mbi.Protect);
        if (withRefs) DumpPointerRefs(hits[i]);
    }
}

static void PatchToBuffaloGap()
{
    const size_t oldLen = std::strlen(kDesertHills);
    const size_t newLen = std::strlen(kBuffaloGap);
    auto hits = FindWritableCString(kDesertHills);
    Log("---- PATCH REQUEST: Desert Hills -> Buffalo Gap; hits=%zu ----", hits.size());
    if (newLen > oldLen) {
        Log("internal error: replacement is longer than source");
        return;
    }
    for (uintptr_t addr : hits) {
        __try {
            std::memcpy(reinterpret_cast<void*>(addr), kBuffaloGap, newLen);
            std::memset(reinterpret_cast<void*>(addr + newLen), 0, oldLen + 1 - newLen);
            gPatched.push_back(addr);
            Log("  patched 0x%08X", (unsigned)addr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("  FAILED to patch 0x%08X", (unsigned)addr);
        }
    }
    FlushInstructionCache(GetCurrentProcess(), nullptr, 0);
    MessageBeep(MB_OK);
}

static void RestorePatched()
{
    const size_t oldLen = std::strlen(kDesertHills);
    Log("---- RESTORE REQUEST: %zu recorded patch(es) ----", gPatched.size());
    for (uintptr_t addr : gPatched) {
        __try {
            std::memcpy(reinterpret_cast<void*>(addr), kDesertHills, oldLen + 1);
            Log("  restored 0x%08X", (unsigned)addr);
        }
        __except (EXCEPTION_EXECUTE_HANDLER) {
            Log("  FAILED to restore 0x%08X", (unsigned)addr);
        }
    }
    gPatched.clear();
}

static DWORD WINAPI ProbeThread(LPVOID)
{
    char exePath[MAX_PATH]{};
    GetModuleFileNameA(nullptr, exePath, MAX_PATH);
    Log("NFSTR ITC Runtime Probe v1");
    Log("EXE: %s", exePath);
    Log("Hotkeys: F6=state+scan, F7=scan+pointer refs, F8=patch live DesertHills strings to BuffaloGap, F9=restore");
    DumpState();

    bool prevF6=false, prevF7=false, prevF8=false, prevF9=false;
    std::string lastLevel;
    while (gRunning) {
        std::string now = SafeCString(kGameCurrentLevel);
        if (now != lastLevel && now != "<unreadable>") {
            Log("LEVEL CHANGE: %s", now.c_str());
            lastLevel = now;
        }

        bool f6 = (GetAsyncKeyState(VK_F6) & 0x8000) != 0;
        bool f7 = (GetAsyncKeyState(VK_F7) & 0x8000) != 0;
        bool f8 = (GetAsyncKeyState(VK_F8) & 0x8000) != 0;
        bool f9 = (GetAsyncKeyState(VK_F9) & 0x8000) != 0;
        if (f6 && !prevF6) { DumpState(); ScanDesertHills(false); }
        if (f7 && !prevF7) { DumpState(); ScanDesertHills(true); }
        if (f8 && !prevF8) { DumpState(); ScanDesertHills(true); PatchToBuffaloGap(); }
        if (f9 && !prevF9) { RestorePatched(); DumpState(); }
        prevF6=f6; prevF7=f7; prevF8=f8; prevF9=f9;
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID)
{
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(module);
        gLog = std::fopen("NFSTR_ITC_RuntimeProbe.log", "w");
        HANDLE h = CreateThread(nullptr, 0, ProbeThread, nullptr, 0, nullptr);
        if (h) CloseHandle(h);
    } else if (reason == DLL_PROCESS_DETACH) {
        gRunning = false;
        if (gLog) {
            Log("DLL detach");
            std::fclose(gLog);
            gLog = nullptr;
        }
    }
    return TRUE;
}
