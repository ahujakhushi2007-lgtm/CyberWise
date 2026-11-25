package com.cyberwise.service;

import com.cyberwise.analyzer.AnalyzerFactory;
import com.cyberwise.analyzer.ThreatAnalyzer;
import com.cyberwise.exception.CyberWiseException;
import com.cyberwise.model.ScamCategory;
import com.cyberwise.model.ScanResult;

import java.util.HashMap;
import java.util.LinkedList;
import java.util.TreeMap;

/**
 * Orchestrates threat scans, maintains recent scan history in a {@code LinkedList},
 * indexes scans by ID in a {@code HashMap}, and aggregates category analytics in a {@code TreeMap}.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A, Unit 1B, Unit 2A, Unit 2B):</b>
 * Polymorphic invocation via {@code ThreatAnalyzer}, Exception Propagation ({@code throws}),
 * {@code LinkedList} (history queue), {@code HashMap} (ID lookup), {@code TreeMap} (sorted stats),
 * {@code StringBuffer} (audit log).</p>
 */
public class ScanService {

    private static final int MAX_HISTORY_SIZE = 50;

    private final LinkedList<ScanResult> scanHistoryQueue;
    private final HashMap<Integer, ScanResult> scanByIdMap;
    private final TreeMap<String, Integer> categoryFrequencyMap;
    private final StringBuffer sessionAuditLog;

    public ScanService() {
        this.scanHistoryQueue = new LinkedList<ScanResult>();
        this.scanByIdMap = new HashMap<Integer, ScanResult>();
        this.categoryFrequencyMap = new TreeMap<String, Integer>();
        this.sessionAuditLog = new StringBuffer();
    }

    /**
     * Runs a scan using the factory-selected analyzer and records the result in history.
     *
     * @param scanType LINK, SMS, or EMAIL
     * @param payload  raw input text or URL
     * @return completed ScanResult
     * @throws CyberWiseException propagated from validator or analyzer
     */
    public ScanResult runScan(String scanType, String payload) throws CyberWiseException {
        ThreatAnalyzer analyzer = AnalyzerFactory.getAnalyzer(scanType);
        ScanResult result = analyzer.analyze(payload);
        recordHistory(result);
        return result;
    }

    private void recordHistory(ScanResult result) {
        if (this.scanHistoryQueue.size() >= MAX_HISTORY_SIZE) {
            ScanResult oldest = this.scanHistoryQueue.removeLast();
            this.scanByIdMap.remove(Integer.valueOf(oldest.getScanId()));
        }
        this.scanHistoryQueue.addFirst(result);
        this.scanByIdMap.put(Integer.valueOf(result.getScanId()), result);

        String displayCat = ScamCategory.toDisplayName(result.getPrimaryCategory());
        Integer currentCount = this.categoryFrequencyMap.get(displayCat);
        int updated = (currentCount == null ? 0 : currentCount.intValue()) + 1;
        this.categoryFrequencyMap.put(displayCat, Integer.valueOf(updated));

        this.sessionAuditLog.append(result.toString()).append("\n");
    }

    public LinkedList<ScanResult> getScanHistoryQueue() {
        return this.scanHistoryQueue;
    }

    public ScanResult findScanById(int scanId) {
        return this.scanByIdMap.get(Integer.valueOf(scanId));
    }

    public TreeMap<String, Integer> getCategoryFrequencyMap() {
        return this.categoryFrequencyMap;
    }

    public String getSessionAuditLog() {
        return this.sessionAuditLog.toString();
    }
}
