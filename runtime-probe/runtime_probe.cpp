#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <cstdint>
#include <cstdarg>
#include <cstring>
#include <vector>
#include <string>
#include <mutex>
#include <algorithm>
#include <cctype>

#pragma comment(lib, "Psapi.lib")

static constexpr uintptr_t kGameCurrentLevel = 0x0289BDC8;
static constexpr uintptr_t kPersistentMin = 0xF0000000u;
static const char* kDesertHills = "_c4/Levels/Level_0500_DesertHills/Level_0500_DesertHills";

static FILE* gLog = nullptr;
static std::mutex gLogMutex;
static std::vector<uintptr_t> gCandidates;
static volatile bool gRunning = true;

static void Log(const char* fmt, ...)
{
    std::lock_guard<std::mutex> lock(gLogMutex);
    if (!gLog) return;
    SYSTEMTIME st{}; GetLocalTime(&st);
    std::fprintf(gLog, "[%02u:%02u:%02u.%03u] ", st.wHour, st.wMinute, st.wSecond, st.wMilliseconds);
    va_list args; va_start(args, fmt); std::vfprintf(gLog, fmt, args); va_end(args);
    std::fputc('\n', gLog); std::fflush(gLog);
}

static bool IsReadable(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READONLY || p == PAGE_READWRITE || p == PAGE_WRITECOPY ||
           p == PAGE_EXECUTE_READ || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static bool IsWritable(DWORD p)
{
    if (p & PAGE_GUARD) return false;
    p &= 0xFF;
    return p == PAGE_READWRITE || p == PAGE_WRITECOPY || p == PAGE_EXECUTE_READWRITE || p == PAGE_EXECUTE_WRITECOPY;
}

static std::string SafeCString(uintptr_t addr, size_t maxLen=260)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!addr || !VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT || !IsReadable(mbi.Protect)) return "<unreadable>";
    size_t avail = (uintptr_t)mbi.BaseAddress + mbi.RegionSize - addr;
    size_t want = std::min(maxLen, avail);
    std::vector<char> b(want);
    SIZE_T got=0;
    if (!ReadProcessMemory(GetCurrentProcess(), (LPCVOID)addr, b.data(), want, &got) || !got) return "<unreadable>";
    size_t n=0; while (n<got && b[n]) ++n;
    if (n==got) return "<unterminated>";
    return std::string(b.data(), n);
}

static std::string MappedFileFor(uintptr_t addr)
{
    char path[2048]{};
    DWORD n = GetMappedFileNameA(GetCurrentProcess(), (LPVOID)addr, path, (DWORD)sizeof(path));
    if (!n) return "<none>";
    return std::string(path, path + n);
}

static void LogAddressInfo(const char* label, uintptr_t addr, uintptr_t relativeTo=0)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)addr, &mbi, sizeof(mbi))) {
        Log("%s 0x%08X: VirtualQuery failed err=%lu", label, (unsigned)addr, GetLastError());
        return;
    }
    long long delta = relativeTo ? (long long)addr - (long long)relativeTo : 0;
    Log("%s 0x%08X%s%s | regionBase=0x%08X allocBase=0x%08X size=0x%zX type=0x%lX protect=0x%lX mapped=%s",
        label, (unsigned)addr,
        relativeTo ? " delta=" : "",
        relativeTo ? std::to_string(delta).c_str() : "",
        (unsigned)(uintptr_t)mbi.BaseAddress,
        (unsigned)(uintptr_t)mbi.AllocationBase,
        mbi.RegionSize,
        (unsigned long)mbi.Type,
        (unsigned long)mbi.Protect,
        MappedFileFor(addr).c_str());
}

static std::vector<uintptr_t> FindExactCString(const char* needle, bool writableOnly=false, bool persistentOnly=false)
{
    std::vector<uintptr_t> hits;
    const size_t needleLen = std::strlen(needle);
    constexpr size_t kChunk = 1u << 20;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t p = (uintptr_t)si.lpMinimumApplicationAddress;
    uintptr_t end = (uintptr_t)si.lpMaximumApplicationAddress;

    while (p < end) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)p, &mbi, sizeof(mbi))) break;
        uintptr_t base = (uintptr_t)mbi.BaseAddress;
        size_t size = mbi.RegionSize;
        bool protOK = writableOnly ? IsWritable(mbi.Protect) : IsReadable(mbi.Protect);
        if (mbi.State == MEM_COMMIT && mbi.Type != MEM_IMAGE && protOK && size > needleLen) {
            std::vector<unsigned char> buf(kChunk + needleLen + 1);
            for (size_t off=0; off<size;) {
                size_t toRead = std::min(kChunk + needleLen, size-off);
                SIZE_T got=0;
                if (ReadProcessMemory(GetCurrentProcess(), (LPCVOID)(base+off), buf.data(), toRead, &got) && got > needleLen) {
                    size_t primary = std::min(kChunk, (size_t)got);
                    for (size_t i=0; i<primary && i+needleLen<got; ++i) {
                        if (buf[i] == (unsigned char)needle[0] && std::memcmp(buf.data()+i, needle, needleLen)==0 && buf[i+needleLen]==0) {
                            uintptr_t a = base+off+i;
                            if (!persistentOnly || a >= kPersistentMin) hits.push_back(a);
                            i += needleLen;
                        }
                    }
                }
                if (size-off <= kChunk) break;
                off += kChunk;
            }
        }
        if (base+size <= p) break;
        p = base+size;
    }
    std::sort(hits.begin(), hits.end());
    hits.erase(std::unique(hits.begin(), hits.end()), hits.end());
    return hits;
}

static std::vector<uintptr_t> FindBytes(const unsigned char* needle, size_t needleLen, size_t limit=64)
{
    std::vector<uintptr_t> hits;
    constexpr size_t kChunk = 1u << 20;
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t p=(uintptr_t)si.lpMinimumApplicationAddress, end=(uintptr_t)si.lpMaximumApplicationAddress;
    while (p<end && hits.size()<limit) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)p,&mbi,sizeof(mbi))) break;
        uintptr_t base=(uintptr_t)mbi.BaseAddress; size_t size=mbi.RegionSize;
        if (mbi.State==MEM_COMMIT && mbi.Type!=MEM_IMAGE && IsReadable(mbi.Protect) && size>=needleLen) {
            std::vector<unsigned char> buf(kChunk+needleLen);
            for (size_t off=0; off<size && hits.size()<limit;) {
                size_t toRead=std::min(kChunk+needleLen-1,size-off); SIZE_T got=0;
                if (ReadProcessMemory(GetCurrentProcess(),(LPCVOID)(base+off),buf.data(),toRead,&got) && got>=needleLen) {
                    size_t primary=std::min(kChunk,(size_t)got);
                    for (size_t i=0;i<primary && i+needleLen<=got;++i) {
                        if (std::memcmp(buf.data()+i,needle,needleLen)==0) {
                            hits.push_back(base+off+i);
                            if (hits.size()>=limit) break;
                            i += needleLen-1;
                        }
                    }
                }
                if (size-off<=kChunk) break;
                off+=kChunk;
            }
        }
        if (base+size<=p) break;
        p=base+size;
    }
    return hits;
}

static std::vector<uintptr_t> FindPersistent()
{
    return FindExactCString(kDesertHills, true, true);
}

static void Scan()
{
    gCandidates = FindPersistent();
    Log("---- PERSISTENT DESERT HILLS CANDIDATES: %zu ----", gCandidates.size());
    for (size_t i=0;i<gCandidates.size();++i) Log("  candidate[%zu] = 0x%08X", i, (unsigned)gCandidates[i]);
    if (gCandidates.size()!=12) {
        Log("WARNING: expected 12 persistent candidates on a clean frontend visit");
        MessageBeep(MB_ICONHAND);
    } else {
        Log("SCAN COMPLETE: 12 candidates cached; candidate 3 = 0x%08X", (unsigned)gCandidates[3]);
        MessageBeep(MB_ICONASTERISK);
    }
}

static void DumpAsciiNeighborhood(uintptr_t target)
{
    MEMORY_BASIC_INFORMATION mbi{};
    if (!VirtualQuery((LPCVOID)target,&mbi,sizeof(mbi)) || mbi.State!=MEM_COMMIT || !IsReadable(mbi.Protect)) return;
    uintptr_t regionStart=(uintptr_t)mbi.BaseAddress;
    uintptr_t regionEnd=regionStart+mbi.RegionSize;
    uintptr_t start=target>0x800 ? target-0x800 : target;
    if (start<regionStart) start=regionStart;
    uintptr_t end=std::min(regionEnd,target+0x800);
    size_t len=(size_t)(end-start);
    std::vector<unsigned char> b(len); SIZE_T got=0;
    if (!ReadProcessMemory(GetCurrentProcess(),(LPCVOID)start,b.data(),len,&got) || !got) return;
    Log("---- PRINTABLE STRINGS WITHIN +/-0x800 OF CANDIDATE 3 ----");
    for (size_t i=0;i<got;) {
        size_t j=i;
        while (j<got && b[j]>=0x20 && b[j]<=0x7e) ++j;
        if (j-i>=4) {
            std::string s((char*)b.data()+i,(char*)b.data()+j);
            Log("  0x%08X delta=%lld : %s",(unsigned)(start+i),(long long)(start+i)-(long long)target,s.c_str());
        }
        i=(j>i)?j+1:i+1;
    }
}

static void DumpPointerRefs(uintptr_t target)
{
    Log("---- 32-BIT POINTER REFERENCES TO CANDIDATE 3 (limit 128) ----");
    SYSTEM_INFO si{}; GetSystemInfo(&si);
    uintptr_t p=(uintptr_t)si.lpMinimumApplicationAddress, end=(uintptr_t)si.lpMaximumApplicationAddress;
    constexpr size_t kChunk=1u<<20;
    unsigned count=0;
    uint32_t t=(uint32_t)target;
    while (p<end && count<128) {
        MEMORY_BASIC_INFORMATION mbi{};
        if (!VirtualQuery((LPCVOID)p,&mbi,sizeof(mbi))) break;
        uintptr_t base=(uintptr_t)mbi.BaseAddress; size_t size=mbi.RegionSize;
        if (mbi.State==MEM_COMMIT && IsReadable(mbi.Protect) && size>=4) {
            std::vector<unsigned char> buf(kChunk+4);
            for (size_t off=0;off<size && count<128;) {
                size_t toRead=std::min(kChunk+3,size-off); SIZE_T got=0;
                if (ReadProcessMemory(GetCurrentProcess(),(LPCVOID)(base+off),buf.data(),toRead,&got) && got>=4) {
                    size_t primary=std::min(kChunk,(size_t)got);
                    for (size_t i=0;i+4<=primary;++i) {
                        uint32_t v=0; std::memcpy(&v,buf.data()+i,4);
                        if (v==t) {
                            uintptr_t at=base+off+i;
                            LogAddressInfo("  ptrref",at,target);
                            ++count;
                            i+=3;
                            if (count>=128) break;
                        }
                    }
                }
                if (size-off<=kChunk) break;
                off+=kChunk;
            }
        }
        if (base+size<=p) break;
        p=base+size;
    }
    Log("POINTER REF TOTAL (capped): %u",count);
}

static void SearchKnownSLE1Strings(uintptr_t target)
{
    const char* needles[] = {
        "_c4/Gameplay/ChallengeSeries/SLE/SLE_1",
        "ID_CS_SLE_1_NAME",
        "ID_CARFILTER_TIER4_SLE_1",
        "CSLE_1",
        "ID_CS_SLE_1_DESC",
        "_c4/Levels/Level_0500_DesertHills/Level_0500_DesertHills"
    };
    Log("---- KNOWN SLE_1 STRING LOCATIONS ----");
    for (const char* s: needles) {
        auto hits=FindExactCString(s,false,false);
        Log("needle '%s' => %zu exact C-string hit(s)",s,hits.size());
        size_t show=std::min<size_t>(hits.size(),32);
        for (size_t i=0;i<show;++i) LogAddressInfo("    hit",hits[i],target);
        if (hits.size()>show) Log("    ... %zu more omitted",hits.size()-show);
    }
}

static void SearchSLE1Guid(uintptr_t target)
{
    // SLE_1 primary instance GUID: 366c5ec1-aff8-4499-a072-0c3ce342800f
    const unsigned char guidLE[16] = {0xC1,0x5E,0x6C,0x36,0xF8,0xAF,0x99,0x44,0xA0,0x72,0x0C,0x3C,0xE3,0x42,0x80,0x0F};
    const unsigned char guidBE[16] = {0x36,0x6C,0x5E,0xC1,0xAF,0xF8,0x44,0x99,0xA0,0x72,0x0C,0x3C,0xE3,0x42,0x80,0x0F};
    auto le=FindBytes(guidLE,16,64);
    auto be=FindBytes(guidBE,16,64);
    Log("---- SLE_1 INSTANCE GUID SEARCH ----");
    Log("little-endian GUID form: %zu hit(s)",le.size());
    for (auto a:le) LogAddressInfo("    LE",a,target);
    Log("canonical/network byte form: %zu hit(s)",be.size());
    for (auto a:be) LogAddressInfo("    BE",a,target);
}

static void InspectCandidate3()
{
    if (gCandidates.size()!=12) Scan();
    if (gCandidates.size()!=12) {
        Log("INSPECT ABORTED: need exactly 12 candidates from a clean frontend scan");
        MessageBeep(MB_ICONHAND);
        return;
    }
    uintptr_t target=gCandidates[3];
    Log("============================================================");
    Log("===== READ-ONLY OWNERSHIP TRACE: CANDIDATE 3 =====");
    Log("No game memory will be modified by this operation.");
    LogAddressInfo("candidate3",target);
    Log("candidate3 string = %s",SafeCString(target).c_str());
    DumpAsciiNeighborhood(target);
    DumpPointerRefs(target);
    SearchKnownSLE1Strings(target);
    SearchSLE1Guid(target);
    Log("===== OWNERSHIP TRACE COMPLETE =====");
    MessageBeep(MB_OK);
}

static DWORD WINAPI Thread(LPVOID)
{
    char exe[MAX_PATH]{}; GetModuleFileNameA(nullptr,exe,MAX_PATH);
    Log("============================================================");
    Log("===== NEW GAME SESSION | PID %lu =====",GetCurrentProcessId());
    Log("NFSTR ITC Runtime Probe v8 - candidate 3 ownership tracer");
    Log("EXE: %s",exe);
    Log("Log mode: APPEND");
    Log("READ-ONLY BUILD: no WriteProcessMemory calls are used.");
    Log("Hotkeys: F6=scan+beep; F7=trace candidate 3 ownership+beep when finished");
    bool p6=false,p7=false;
    std::string last;
    while (gRunning) {
        std::string now=SafeCString(kGameCurrentLevel);
        if (now!=last && now!="<unreadable>") { Log("LEVEL CHANGE: %s",now.c_str()); last=now; }
        bool f6=(GetAsyncKeyState(VK_F6)&0x8000)!=0;
        bool f7=(GetAsyncKeyState(VK_F7)&0x8000)!=0;
        if (f6&&!p6) Scan();
        if (f7&&!p7) InspectCandidate3();
        p6=f6; p7=f7;
        Sleep(100);
    }
    return 0;
}

BOOL APIENTRY DllMain(HMODULE m,DWORD r,LPVOID)
{
    if (r==DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(m);
        fopen_s(&gLog,"NFSTR_ITC_RuntimeProbe.log","a");
        HANDLE h=CreateThread(nullptr,0,Thread,nullptr,0,nullptr); if(h) CloseHandle(h);
    } else if (r==DLL_PROCESS_DETACH) {
        gRunning=false;
        if (gLog) { std::fflush(gLog); std::fclose(gLog); gLog=nullptr; }
    }
    return TRUE;
}
