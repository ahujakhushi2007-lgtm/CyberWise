# 🛡️ CyberWise — Java Terminal Backend Edition

> **Course: 25CSE0202 / Programming in Java (Chitkara University)**  
> **Milestone: Continuous Assessment 3 (CA-3) Project Evaluation (Lectures 1–54)**  
> **Architecture: Pure Core Java Console Application • Zero External JAR Dependencies**

---

## 📌 Project Overview
**CyberWise** is an India-first terminal-based cybersecurity detection engine developed in Java. It analyzes URLs, SMS, WhatsApp messages, and raw emails to compute an animated risk score (0–100), issue forensic verdicts (`SAFE`, `SUSPICIOUS`, `DANGEROUS`), and flag sophisticated fraud patterns including:
- **Digital Arrest & Police Extortion Threats** (CBI / Supreme Court video custody scams)
- **UPI PIN Traps & Reverse QR Code Phishing** (PhonePe / GPay fake cashback)
- **Electricity Disconnection 9:30 PM Threats** (Devanagari Hindi & Hinglish Discom notices)
- **Fake Bank / SIM KYC Suspension Notices** (SBI YONO, HDFC, PAN card update traps)
- **Telegram Part-time Tasks & YouTube Like Scams** (₹3,000–₹8,000 daily reward funnels)
- **RFC 822 Email Spoofing & Header Discrepancies** (SPF/DKIM/DMARC failures, display-name spoofing)

---

## 🎓 Syllabus Mapping to Lectures 1–54 (Continuous Assessment 1 to 3)

This project strictly adheres to the Chitkara University Course Plan and utilizes only topics taught up to **Lecture 54**:

| Module & Lectures | Syllabus Topics | Implementation in CyberWise |
| :--- | :--- | :--- |
| **Lect. 1–5** | OOP Concepts, Classes, Objects, Methods, Constructors, `this`/`static`, Inheritance, Polymorphism, Abstraction, Interfaces | `ThreatAnalyzer<T>` interface, `BaseAnalyzer<T>` abstract class extended by `UrlAnalyzer` & `TextAnalyzer`, encapsulation in `Finding` and `AnalysisResult`. |
| **Lect. 6–9** | String Immutability, String pool, search, manipulation, formatting, `StringBuilder`, wrapper classes | Levenshtein distance matrix algorithm, lookalike character normalization (`rn`→`m`, `0`→`o`), ASCII banner & progress gauge formatting via `StringBuilder`. |
| **Lect. 10–12** | Checked & unchecked exceptions, `try-catch-finally`, exception propagation, custom exceptions | `InvalidInputException` (checked exception for input validation) and `ScanExecutionException` (runtime exception). |
| **Lect. 13–15** | Integrated console program, input validation, debugging, test structures | Menu-driven `TerminalUI` with ANSI color formatting, validation checks, and scanner error handling. |
| **Lect. 16–19** | Collections Framework (`ArrayList`, `HashSet`, `LinkedHashSet`) | `ArrayList` for storing red flag findings, `HashSet` for blacklisted TLDs (`.xyz`, `.top`, `.icu`) and shorteners. |
| **Lect. 20–22** | `HashMap`, `LinkedHashMap`, traversal using iterators | `BrandRegistry` dictionary storing 45+ Indian banks and brands with official domains, keywords, and typos. |
| **Lect. 23–25** | `Comparable`, `Comparator`, sorting, Collections utilities | `AnalysisResult` implements `Comparable<AnalysisResult>` for natural descending risk ranking; `Finding` sorted by severity comparator. |
| **Lect. 26–29** | Multithreading, `Thread`, `Runnable`, `start()`, `run()`, `join()`, `sleep()`, daemon threads, priorities | `ConcurrentBatchScanner` runs 4 parallel worker threads to scan URLs concurrently with `.join()`; `RadarProgressAnimator` runs on a background Daemon Thread. |
| **Lect. 30–31** | Synchronization, race conditions, critical sections, `synchronized` blocks | `ConcurrentBatchScanner` uses `synchronized(urlQueue)` and `synchronized(synchronizedResults)` to safely prevent race conditions during parallel processing. |
| **Lect. 43–46** | Lambda Expressions & Stream API (`filter()`, `map()`, `sorted()`, method references) | `BenchmarkRunner` uses Stream pipelines and lambdas to evaluate 35 test cases, filter outcomes, and calculate accuracy, precision, and recall. |
| **Lect. 47–48** | Generics, type safety, diamond operator `<>` | Generic interface `ThreatAnalyzer<T>` and abstract class `BaseAnalyzer<T>` enabling reusable typed threat analyzers. |
| **Lect. 49–54** | File Handling, `BufferedReader`, `BufferedWriter`, try-with-resources, CSV integration | `FileReportManager` uses `BufferedWriter` with try-with-resources to persist audit trails into `cyberwise_history.csv` and export formatted `threat_report.txt`. |

---

## 📂 Directory Structure

```text
java/
├── src/
│   └── com/
│       └── cyberwise/
│           ├── analyzer/
│           │   ├── ThreatAnalyzer.java        # Generic Interface (Lect. 1-5, 47-48)
│           │   ├── BaseAnalyzer.java          # Abstract Class with validation (Lect. 1-5)
│           │   ├── UrlAnalyzer.java           # Levenshtein, Punycode, Typosquatting (Lect. 6-9)
│           │   ├── TextAnalyzer.java          # Regex coercion & Indian threat vectors (Lect. 6-9)
│           │   └── EmailAnalyzer.java         # RFC 822 parser & SPF/DKIM verification
│           ├── benchmark/
│           │   ├── BenchmarkCase.java         # Model for test samples
│           │   └── BenchmarkRunner.java       # Stream API evaluation of 35 cases (Lect. 43-46)
│           ├── cli/
│           │   └── TerminalUI.java            # Console Menu with ANSI colors & ASCII gauge (Lect. 13-15)
│           ├── concurrency/
│           │   ├── ConcurrentBatchScanner.java # 4-Thread parallel batch scanner (Lect. 26-31)
│           │   └── RadarProgressAnimator.java # Daemon Thread with sleep() for radar (Lect. 28-29)
│           ├── data/
│           │   └── BrandRegistry.java         # 45+ Brands, HashMap/HashSet registries (Lect. 16-22)
│           ├── exception/
│           │   ├── InvalidInputException.java # Checked Custom Exception (Lect. 10-12)
│           │   └── ScanExecutionException.java # Unchecked Custom Exception (Lect. 10-12)
│           ├── model/
│           │   ├── AnalysisResult.java        # Implements Comparable<AnalysisResult> (Lect. 23-25)
│           │   ├── Brand.java                 # Model entity
│           │   ├── Finding.java               # Red flag evidence entity
│           │   └── Verdict.java               # Enum: SAFE, SUSPICIOUS, DANGEROUS
│           ├── storage/
│           │   └── FileReportManager.java     # BufferedReader/Writer CSV persistence (Lect. 49-54)
│           └── Main.java                      # Console Application Entry Point
├── run.sh                                     # 1-Click Launch Script (macOS / Linux)
├── run.bat                                    # 1-Click Launch Script (Windows)
└── README_JAVA.md                             # Academic Submission Guide & Documentation
```

---

## ⚡ How to Compile and Run

### Option 1: Using the provided launcher script
```bash
cd java
./run.sh
```
*(On Windows: double-click `run.bat` or run `run.bat` from Command Prompt)*

### Option 2: Using standard javac command
```bash
cd java
mkdir -p bin
javac -d bin $(find src -name "*.java")
java -cp bin com.cyberwise.Main
```

---

## 📊 Empirical Benchmark Evaluation (35 Curated Test Cases)

Run Option `6` in the main menu to execute the benchmark suite live:

| Metric | Score | Validation Standard |
| :--- | :--- | :--- |
| **Accuracy** | **100.00%** | (TP + TN) / Total (35/35 correct) |
| **Precision** | **100.00%** | Zero false alarms on legitimate banking notifications |
| **Recall** | **100.00%** | Zero missed fraud attempts |
| **F1 Score** | **100.00%** | Harmonic mean of precision & recall |
| **Evaluated Cases** | **35 Samples** | 19 Malicious payloads + 16 Authentic samples |

---

## 💡 Common Viva Questions & Answers for Students

1. **Q: Why did you use an interface `ThreatAnalyzer<T>` and an abstract class `BaseAnalyzer<T>`?**  
   *A:* An interface establishes a contract ensuring every threat detector implements `analyze()`, while `BaseAnalyzer<T>` provides code reuse via the Template Method pattern, performing standard input validation before delegating to `doAnalyze()`.

2. **Q: How does `Comparable<AnalysisResult>` work in your project?**  
   *A:* In `AnalysisResult`, `compareTo()` compares risk scores in reverse order (`Integer.compare(other.riskScore, this.riskScore)`), so calling `Collections.sort()` automatically ranks the highest-risk threats at the top.

3. **Q: How did you handle multithreading and prevent race conditions?**  
   *A:* In `ConcurrentBatchScanner`, multiple worker threads retrieve URLs from a shared queue and store results in a shared list. We wrapped queue access and result accumulation inside `synchronized` blocks to ensure mutual exclusion and prevent race conditions.

4. **Q: How is file handling implemented safely?**  
   *A:* In `FileReportManager`, we use `BufferedWriter` wrapped inside a `try-with-resources` block, ensuring that stream file descriptors are automatically closed even if an `IOException` occurs.

