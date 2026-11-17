package com.cyberwise.concurrency;

import com.cyberwise.analyzer.UrlAnalyzer;
import com.cyberwise.model.AnalysisResult;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * Demonstrates Multithreading, Concurrency, and Synchronization (Lectures 26-31).
 * Multiple worker threads scan URLs in parallel and synchronize on a shared results list.
 */
public class ConcurrentBatchScanner {

    private final List<String> urlQueue;
    private final List<AnalysisResult> synchronizedResults;
    private final int threadCount;

    public ConcurrentBatchScanner(List<String> urls, int threadCount) {
        this.urlQueue = new ArrayList<>(urls);
        this.synchronizedResults = Collections.synchronizedList(new ArrayList<>());
        this.threadCount = Math.max(1, Math.min(threadCount, 8));
    }

    /**
     * Executes parallel multithreaded scanning using Thread and Runnable with join()
     */
    public List<AnalysisResult> executeBatchScan() {
        List<Thread> workers = new ArrayList<>();
        final int total = urlQueue.size();

        for (int i = 0; i < threadCount; i++) {
            final int workerId = i + 1;
            Thread worker = new Thread(new Runnable() {
                @Override
                public void run() {
                    while (true) {
                        String urlToScan = null;
                        // Synchronized critical section to prevent race conditions on queue (Lectures 30-31)
                        synchronized (urlQueue) {
                            if (!urlQueue.isEmpty()) {
                                urlToScan = urlQueue.remove(0);
                            }
                        }

                        if (urlToScan == null) {
                            break; // All tasks processed
                        }

                        // Independent worker thread scan execution
                        AnalysisResult res = UrlAnalyzer.scan(urlToScan);
                        res.setMode("Multithreaded Worker #" + workerId);

                        // Synchronized list insertion (atomicity awareness)
                        synchronized (synchronizedResults) {
                            synchronizedResults.add(res);
                        }

                        try {
                            // Small timed sleep simulation (Lecture 26-29)
                            Thread.sleep(15);
                        } catch (InterruptedException e) {
                            Thread.currentThread().interrupt();
                            break;
                        }
                    }
                }
            }, "CyberWise-Worker-" + workerId);

            worker.setPriority(Thread.NORM_PRIORITY);
            workers.add(worker);
            worker.start(); // Thread state transitions from NEW to RUNNABLE
        }

        // Wait for all worker threads to complete using join() (Lectures 26-27)
        for (Thread worker : workers) {
            try {
                worker.join(); // Blocks caller until worker thread state reaches TERMINATED
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                System.err.println("Batch scan worker interrupted: " + worker.getName());
            }
        }

        // Sort descending by risk score using natural Comparable (Lectures 23-25)
        Collections.sort(synchronizedResults);
        return new ArrayList<>(synchronizedResults);
    }
}
