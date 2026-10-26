#include <windows.h>
#include <iostream>
#include <string>
#include "./report/DetectionEngine.h"
#include "./system/PrivilegeManager.h"

int main()
{
    // 1. Try to enable SeDebugPrivilege so we can open more processes.
    //    If this fails (not elevated), we carry on and scan what we can.
    if (!PrivilegeManager::turnOnPrivilege(L"SeDebugPrivilege")) {
        std::wcout << L"[!] Could not enable SeDebugPrivilege - "
                      L"run as admin to scan more processes.\n";
    }

    if (!PrivilegeManager::isProcessElevated()) {
        std::wcout << L"[!] Not elevated - many processes will be inaccessible.\n";
    }

    // 2. Run the full scan.
    std::wcout << L"Scanning...\n\n";
    DetectionEngine engine;
    std::vector<Finding> findings = engine.analyzeAll();

    // 3. Print every finding (raw - ConsoleReporter will format this later).
    for (const Finding& f : findings) {
        std::wcout << L"[" << severityName(f.severity) << L"] "
                   << f.processName << L" (pid " << f.pid << L")\n"
                   << L"    rule:     " << f.ruleId.c_str() << L"\n"
                   << L"    message:  " << f.message.c_str() << L"\n"
                   << L"    evidence: " << f.evidence.c_str() << L"\n\n";
    }

    // 4. The census line - the honest summary.
    std::wcout << L"----------------------------------------\n"
               << L"Findings:     " << findings.size() << L"\n"
               << L"Scanned:      " << engine.scannedCount() << L"\n"
               << L"Inaccessible: " << engine.inaccessibleCount() << L"\n";

    return 0;
    std::cout<<"DHJDJ"<<std::endl;
}