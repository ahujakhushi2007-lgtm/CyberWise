package com.cyberwise.storage;

import com.cyberwise.model.AnalysisResult;
import com.cyberwise.model.Finding;
import com.cyberwise.model.Verdict;

import java.io.*;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Date;
import java.util.List;

/**
 * File Handling and Collections Integration (Lectures 49-54).
 * Handles text/CSV export/import using BufferedReader, BufferedWriter, and try-with-resources.
 */
public class FileReportManager {

    private static final String CSV_FILE = "cyberwise_history.csv";

    /**
     * Appends a scan result to the persistent CSV audit file using BufferedWriter
     */
    public static synchronized void saveToCsv(AnalysisResult result) {
        File file = new File(CSV_FILE);
        boolean isNew = !file.exists();

        // Exception-safe try-with-resources (Lectures 10-12, 49-54)
        try (BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(
                new FileOutputStream(file, true), StandardCharsets.UTF_8))) {

            if (isNew) {
                writer.write("Timestamp,Type,Verdict,RiskScore,Target,ScamType,Brand\n");
            }

            String cleanTarget = result.getTarget().replace("\"", "\"\"").replace("\n", " ");
            if (cleanTarget.length() > 60) {
                cleanTarget = cleanTarget.substring(0, 57) + "...";
            }

            String line = String.format("%s,%s,%s,%d,\"%s\",%s,%s\n",
                new Date(result.getTimestamp()).toString(),
                result.getArtifactType(),
                result.getVerdict(),
                result.getRiskScore(),
                cleanTarget,
                result.getScamType() != null ? result.getScamType() : "N/A",
                result.getImpersonatedBrand() != null ? result.getImpersonatedBrand() : "N/A"
            );

            writer.write(line);
            writer.flush();
        } catch (IOException e) {
            System.err.println("Warning: Could not save scan to CSV: " + e.getMessage());
        }
    }

    /**
     * Reads scan history from persistent CSV using BufferedReader and maps into a List collection (Lectures 49-54)
     */
    public static List<String[]> loadHistoryFromCsv() {
        List<String[]> records = new ArrayList<>();
        File file = new File(CSV_FILE);
        if (!file.exists()) return records;

        try (BufferedReader reader = new BufferedReader(new InputStreamReader(
                new FileInputStream(file), StandardCharsets.UTF_8))) {

            String line;
            boolean isHeader = true;
            while ((line = reader.readLine()) != null) {
                if (isHeader) {
                    isHeader = false;
                    continue;
                }
                if (!line.trim().isEmpty()) {
                    // Split CSV row
                    String[] parts = line.split(",(?=(?:[^\"]*\"[^\"]*\")*[^\"]*$)");
                    records.add(parts);
                }
            }
        } catch (IOException e) {
            System.err.println("Error reading CSV history: " + e.getMessage());
        }
        return records;
    }

    /**
     * Generates a formal text-based incident report file using FileWriter (Lectures 49-51)
     */
    public static String exportTextReport(AnalysisResult result, String filename) {
        File file = new File(filename);
        try (BufferedWriter writer = new BufferedWriter(new FileWriter(file, StandardCharsets.UTF_8))) {
            writer.write("============================================================\n");
            writer.write("🛡️  PHISHSHIELD AI — FORENSIC INCIDENT AUDIT REPORT\n");
            writer.write("============================================================\n");
            writer.write("Timestamp:     " + new Date(result.getTimestamp()) + "\n");
            writer.write("Artifact Type: " + result.getArtifactType() + "\n");
            writer.write("Target Input:  " + result.getTarget() + "\n");
            writer.write("Verdict:       " + result.getVerdict() + "\n");
            writer.write("Risk Score:    " + result.getRiskScore() + " / 100\n");
            writer.write("Scam Vector:   " + (result.getScamType() != null ? result.getScamType() : "None") + "\n");
            writer.write("Impersonated:  " + (result.getImpersonatedBrand() != null ? result.getImpersonatedBrand() : "None") + "\n");
            writer.write("Engine Mode:   " + result.getMode() + "\n");
            writer.write("------------------------------------------------------------\n");
            writer.write("Summary Explanation:\n");
            writer.write(result.getExplanation() + "\n");
            writer.write("\nHindi Explanation:\n");
            writer.write(result.getExplanationHi() + "\n");
            writer.write("------------------------------------------------------------\n");
            writer.write("Key Red Flag Findings (" + result.getFindings().size() + "):\n");
            for (Finding f : result.getFindings()) {
                writer.write(" • [" + f.getSeverity() + "] " + f.getTitle() + " (+" + f.getScore() + " pts)\n");
                writer.write("   " + f.getDescription() + "\n");
            }
            writer.write("------------------------------------------------------------\n");
            writer.write("Recommended Defense Actions:\n");
            for (String a : result.getRecommendedActions()) {
                writer.write(" [✓] " + a + "\n");
            }
            writer.write("============================================================\n");
            writer.write("National Cybercrime Helpline: 1930 | Portal: cybercrime.gov.in\n");
            writer.write("============================================================\n");
            writer.flush();
            return file.getAbsolutePath();
        } catch (IOException e) {
            System.err.println("Failed to write report file: " + e.getMessage());
            return null;
        }
    }
}

