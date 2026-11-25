# 🛡️ CyberWise — Explainable India-First Scam Detector (Core Java Unit 1 & 2 Edition)

> **Pure Core Java Console Application** built strictly with **Unit 1 & Unit 2 Java OOP Syllabus Concepts** — zero SQL/databases, zero external APIs, zero GUI/web frameworks, and **40 modular Java classes**.

**Pitch:** *"An explainable, India-first scam detector that tells you not just whether a link, SMS, or email is a scam, but exactly why."*

---

## 1. Problem Statement
Digital fraud in India (fake SBI/HDFC KYC updates, UPI Collect/QR traps, "Digital Arrest" CBI/police extortion calls, FedEx/customs parcel scams, KBC lotteries, and Telegram task scams) often mixes English, Hinglish, and lookalike domains (`sbi-kyc-update.xyz`, `paytm-support.in.net`). Many users cannot tell why a message is dangerous before clicking or sharing an OTP/UPI PIN.

## 2. Objectives & Scope
- **Explainable Scoring (0–100):** Classify inputs as `SAFE` (`0–30`), `SUSPICIOUS` (`31–65`), or `DANGEROUS` (`66–100`) using a transparent 2D risk calibration matrix.
- **Inline Red-Flag Highlighting:** Highlight exact matched fraud phrases/URLs inside the original message in **bold red** ANSI colors with plain-English explanations.
- **India-First Threat Coverage:** Detect fake Indian bank/fintech domains, Hinglish coercion, OTP/PIN/CVV theft, UPI collect traps, Digital Arrest threats, courier customs scams, electricity disconnection scams, and Telegram task scams.
- **Educational & Actionable:** Provide customized India-first next steps (`https://cybercrime.gov.in`, helpline `1930`) plus a built-in Scam Awareness Library.
- **Scope:** Console-based, offline Core Java application adhering strictly to Unit 1 (OOP, Strings, 2D Arrays, Wrapper classes) and Unit 2 (Exceptions, Validation, Testing, Collections Framework).

---

## 3. Architecture

```text
+------------------------------------------------------------------------+
|                        com.cyberwise.Main                              |
|              CLI Args (--test / --demo) & Entry Point                  |
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
|                    com.cyberwise.cli.ConsoleMenu                       |
|   Menu [0-8] | Scanner Multi-Line Input | try-catch-finally & multi-catch
+-----------------------------------+------------------------------------+
                                    |
                                    v
+------------------------------------------------------------------------+
|                   com.cyberwise.service.ScanService                    |
|   History Queue (LinkedList) | ID Map (HashMap) | Stats (TreeMap)      |
+-----------------+----------------------------------+-------------------+
                  |                                  |
                  v                                  v
+-----------------------------------+   +--------------------------------+
|  analyzer.AnalyzerFactory         |   | service.ReportFormatter        |
|  Polymorphic ThreatAnalyzer       |   | StringBuilder + ANSI Highlight |
|   ├─ LinkAnalyzer                 |   +--------------------------------+
|   ├─ SmsTextAnalyzer              |
|   └─ EmailAnalyzer (multilevel)   |
+-----------------+-----------------+
                  |
                  v
+------------------------------------------------------------------------+
|  engine: TextSimilarityEngine (2D int[][] DP) | RuleMatcher            |
|          RiskScoringMatrix (2D int[][] & String[][]) | NextStepsAdvisor|
|  data:   BrandRepository | RuleRepository | AwarenessRepository        |
+------------------------------------------------------------------------+
```

---

## 4. Syllabus Mapping (Unit 1 & Unit 2 — Class & Method Reference)

Every syllabus topic is implemented and also inspectable live inside the app via **Menu Option 8**.

### Unit 1A – Object-Oriented Programming and Java Fundamentals
| Syllabus Topic | Class(es) & Method(s) |
| :--- | :--- |
| **OOP Concepts & Object Modelling** | `BrandProfile`, `RedFlag`, `ScamRule`, `ScanResult`, `AwarenessArticle` |
| **Classes, Objects, Methods & Constructors** | `RedFlag` (overloaded constructors), `ScanResult` (constructor + mutators), `BrandProfile` |
| **`this` and `static` Keywords** | `ScanResult.nextScanId` (`static` counter), `this(...)` constructor chaining in `RedFlag`, `this.field` across models |
| **Inheritance (Single & Multilevel)** | `AbstractThreatAnalyzer -> SmsTextAnalyzer -> EmailAnalyzer`; `CyberWiseException -> InvalidInputException / UnknownMenuOptionException / AwarenessNotFoundException` |
| **Polymorphism (Method Overloading)** | `LinkAnalyzer.analyze(String)` vs `LinkAnalyzer.analyze(String, boolean)`; `ScanResult.addRedFlag(RedFlag)` vs `addRedFlag(String, ...)` |
| **Polymorphism (Method Overriding)** | `LinkAnalyzer.validateInput()`, `LinkAnalyzer.performAnalysis()`, `SmsTextAnalyzer.performAnalysis()`, `EmailAnalyzer.performAnalysis()` (uses `super`), `RedFlag.compareTo()` |
| **Abstraction & Interfaces** | `ThreatAnalyzer` (interface), `AbstractThreatAnalyzer` (abstract class with template method `analyze()` and abstract `performAnalysis()`) |

### Unit 1B – Arrays, Strings, and Wrapper Classes
| Syllabus Topic | Class(es) & Method(s) |
| :--- | :--- |
| **Multi-dimensional Arrays** | `TextSimilarityEngine.computeEditDistance()` (`int[][]` Levenshtein DP matrix), `RiskScoringMatrix.BASELINE_FLOOR_MATRIX` (`int[][]`) & `VERDICT_BANDS` (`String[][]`), `DemoSampleRepository.DEMO_MATRIX` (`String[][]`) |
| **String Immutability & String Pool** | `TextSimilarityEngine.normalizeHomoglyphs()` & `TextSimilarityEngine.demonstrateStringPoolAndImmutability()` (`==` vs `.equals()`) |
| **String Comparison, Searching & Manipulation** | `RuleMatcher.findPhraseWithBoundaries()` (`indexOf`, `substring`, `toLowerCase`), `RuleMatcher.extractUrls()` (`split`, `startsWith`, `contains`), `LinkAnalyzer.extractHost()` |
| **String Formatting** | `ReportFormatter.formatScanReport()`, `TestRunner.runAll()`, `ConsoleMenu.handleViewHistoryAndStats()` (`String.format`, `printf`) |
| **`StringBuilder` & `StringBuffer`** | `ReportFormatter.highlightRedFlags()` & `formatScanReport()` (`StringBuilder`); `ScanResult.traceLog`, `ScanService.sessionAuditLog`, `DebugTracer.SESSION_TRACE` (`StringBuffer`) |
| **Wrapper Classes** | `InputValidator.parseMenuChoice()` (`Integer.parseInt`), `RuleMatcher.findPhraseWithBoundaries()` (`Character.isLetterOrDigit`), `Severity.fromWeight()` (`Integer.valueOf`), `LinkAnalyzer.isIpAddress()` (`Character.isDigit`) |

### Unit 2A – Exception Handling, Validation, Debugging & Testing
| Syllabus Topic | Class(es) & Method(s) |
| :--- | :--- |
| **Checked & Unchecked Exceptions** | Checked: `CyberWiseException`, `InvalidInputException`, `UnknownMenuOptionException`, `AwarenessNotFoundException`; Unchecked: `ScanLimitExceededException` |
| **`try`, `catch`, `finally` & multi-catch** | `ConsoleMenu.start()` (`try-catch-finally`, `catch (UnknownMenuOptionException \| NumberFormatException e)`), `TestRunner.runAll()` |
| **Exception Propagation, `throw` & `throws`** | `InputValidator` -> `AbstractThreatAnalyzer.analyze()` -> `ScanService.runScan()` -> `ConsoleMenu.start()` |
| **Integrated Console Coding & Input Validation** | `ConsoleMenu`, `InputValidator.validateUrl()`, `InputValidator.validateNonEmpty()`, `InputValidator.parseMenuChoice()` |
| **Debugging** | `DebugTracer.toggle()`, `DebugTracer.log()`, Option 8 diagnostic view |
| **Test Cases** | `TestCase`, `TestResult`, `CyberWiseTestSuite.buildScanTestCases()`, `TestRunner.runAll()` (17 automated tests) |

### Unit 2B – Collections Framework
| Collection | Class & Usage Reason |
| :--- | :--- |
| **`ArrayList`** | `ScanResult.redFlags`, `RuleRepository.ALL_RULES`, `CyberWiseTestSuite` — indexed iteration & sorting |
| **`LinkedList`** | `ScanService.scanHistoryQueue` — bounded recent scan queue using `addFirst()` / `removeLast()` |
| **`HashSet`** | `BrandRepository.SUSPICIOUS_TLDS`, `URL_SHORTENERS`, `ALL_OFFICIAL_DOMAINS` — O(1) membership lookups |
| **`LinkedHashSet`** | `ScanResult.triggeredCategories` — unique scam categories preserving detection order |
| **`TreeSet`** | `ScanResult.uniqueMatchedTokens` — unique matched fraud tokens sorted alphabetically |
| **`HashMap`** | `BrandRepository.BRAND_MAP`, `ScanService.scanByIdMap`, `NextStepsAdvisor.ADVICE_MAP` — fast key-value lookup |
| **`LinkedHashMap`** | `AwarenessRepository.ORDERED_ARTICLES`, `RuleRepository.RULES_BY_CATEGORY`, `SyllabusTracker.TOPIC_TO_CODE_MAP` — preserves menu/display order |
| **`TreeMap`** | `ScanService.categoryFrequencyMap` — category scan counts sorted alphabetically by category name |
| **`Comparator` / `Comparable`** | `RedFlag implements Comparable<RedFlag>` and `RedFlagWeightComparator implements Comparator<RedFlag>` |

---

## 5. Project Structure (40 Classes)
```text
src/com/cyberwise/
├── Main.java                                  # Entry point (--test, --demo, interactive mode)
├── analyzer/
│   ├── ThreatAnalyzer.java                    # Interface
│   ├── AbstractThreatAnalyzer.java            # Abstract base template class
│   ├── LinkAnalyzer.java                      # URL, IP, '@', TLD, shortener & 2D typo analysis
│   ├── SmsTextAnalyzer.java                   # SMS/WhatsApp rules + embedded URL scanner
│   ├── EmailAnalyzer.java                     # Multilevel inheritance adding header spoofing checks
│   ├── AnalyzerFactory.java                   # Factory returning ThreatAnalyzer polymorphically
│   └── RedFlagWeightComparator.java           # Comparator sorting RedFlags by weight
├── cli/
│   ├── AnsiPalette.java                       # ANSI color escape codes
│   └── ConsoleMenu.java                       # Interactive Scanner menu (options 0-8)
├── data/
│   ├── BrandRepository.java                   # Official Indian banks/portals + suspicious TLDs
│   ├── RuleRepository.java                    # India-first Hinglish/English scam rules
│   ├── AwarenessRepository.java               # 6 educational India-first scam guides
│   └── DemoSampleRepository.java              # 6 pre-loaded demo payloads
├── engine/
│   ├── TextSimilarityEngine.java              # 2D int[][] Levenshtein + String Pool demo
│   ├── RuleMatcher.java                       # String searching & embedded URL extraction
│   ├── RiskScoringMatrix.java                 # 2D int[][] & String[][] risk matrix
│   ├── NextStepsAdvisor.java                  # Customized cybercrime.gov.in / 1930 advice
│   └── SyllabusTracker.java                   # Live syllabus-to-class mapping
├── exception/
│   ├── CyberWiseException.java                # Base checked custom exception
│   ├── InvalidInputException.java             # Checked input validation exception
│   ├── UnknownMenuOptionException.java        # Checked invalid menu choice exception
│   ├── AwarenessNotFoundException.java        # Checked missing article exception
│   └── ScanLimitExceededException.java        # Unchecked length-limit exception
├── model/
│   ├── VerdictConstants.java                  # SAFE / SUSPICIOUS / DANGEROUS thresholds
│   ├── ScamCategory.java                      # India-first scam category constants
│   ├── Severity.java                          # LOW / MEDIUM / HIGH / CRITICAL helpers
│   ├── BrandProfile.java                      # Brand entity (domains, keywords, typos)
│   ├── RedFlag.java                           # Triggered rule evidence (Comparable)
│   ├── ScamRule.java                          # Offline rule model
│   ├── ScanResult.java                        # Encapsulated scan output
│   └── AwarenessArticle.java                  # Awareness guide model
├── service/
│   ├── ScanService.java                       # Scan orchestration, LinkedList history, TreeMap stats
│   ├── InputValidator.java                    # Wrapper-based validation & exception throwing
│   ├── ReportFormatter.java                   # StringBuilder ANSI report & red-flag highlighter
│   └── DebugTracer.java                       # Toggleable debug logger (StringBuffer)
└── test/
    ├── TestCase.java                          # Test specification model
    ├── TestResult.java                        # Test execution outcome model
    ├── CyberWiseTestSuite.java                # 12 curated scan cases
    └── TestRunner.java                        # Built-in 17-test runner (--test / Option 7)
```

---

## 6. Setup & How to Run

### Prerequisites
- Java JDK 17+ (`javac` and `java`)

### Compile & Run
```bash
./run.sh
```
Or manually:
```bash
mkdir -p bin
javac -encoding UTF-8 -d bin $(find src -name "*.java")
java -cp bin com.cyberwise.Main
```

### Quick Modes
```bash
./run.sh --test    # Run all 17 built-in unit tests
./run.sh --demo    # Run all 6 pre-loaded India scam & safe demo cases
```

---

## 7. Current Status, Milestones & Pending Work
- **Completed Milestones:**
  - M1: Domain models, constants, and 5 checked/unchecked custom exceptions
  - M2: India-first brand registry, offline Hinglish/English rules, awareness library, and demo samples
  - M3: 2D array Levenshtein similarity engine, String Pool diagnostics, and 2D risk calibration matrix
  - M4: Interface + Abstract + Multilevel inheritance analyzers (`LinkAnalyzer`, `SmsTextAnalyzer`, `EmailAnalyzer`) and `AnalyzerFactory`
  - M5: Interactive ANSI console menu, red-flag highlighter, `LinkedList` history, `TreeMap` analytics, and 17-case built-in test runner
- **Pending / Future Enhancements (Beyond Unit 1 & 2 Scope):**
  - Persistence via SQLite/File I/O once covered in later units
  - Optional external AI/vision integration for screenshot OCR
