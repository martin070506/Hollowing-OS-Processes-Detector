#pragma once
#include <vector>
#include <string>
#include <unordered_set>
#include <windows.h>
#include "Finding.h"
#include "../system/ProcessEnumerator.h"
#include "../Const/ProcessInfo.h"
#include "../pe/LiveImage.h"
#include "../pe/DiskImage.h"
#include "../scan/SuspiciousRegion.h"

class DetectionEngine {
public:
    DetectionEngine();

    std::vector<Finding> analyzeAll();
    std::vector<Finding> analyzeProcess(const ProcessInfo& info);

    int scannedCount()      const { return _scanned; }
    int inaccessibleCount() const { return _inaccessible; }

private:
    ProcessEnumerator               _enumerator;
    std::unordered_set<std::wstring> _jitProcesses;   // suppression list
    int _scanned      = 0;
    int _inaccessible = 0;

    void compareHeaders(const LiveImage& live, const DiskImage& disk,
                        const ProcessInfo& info, std::vector<Finding>& out);
    void evaluateRegions(const std::vector<SuspiciousRegion>& regions,
                         const ProcessInfo& info, bool isJit,
                         std::vector<Finding>& out);
    bool isJitProcess(const std::wstring& name) const;
};