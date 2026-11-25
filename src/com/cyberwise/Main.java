package com.cyberwise;

import com.cyberwise.cli.AnsiPalette;
import com.cyberwise.cli.ConsoleMenu;
import com.cyberwise.service.ScanService;
import com.cyberwise.test.TestRunner;

/**
 * Application entry point for CyberWise (Core Java Unit 1 & Unit 2 Edition).
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 1A & Unit 2A):</b>
 * {@code main} entry method, Object Creation, Command-line Arguments,
 * Top-level {@code try-catch} safety net.</p>
 */
public class Main {

    public static void main(String[] args) {
        try {
            if (args != null && args.length > 0) {
                if ("--test".equalsIgnoreCase(args[0])) {
                    boolean allPassed = TestRunner.runAll();
                    System.exit(allPassed ? 0 : 1);
                }
                if ("--demo".equalsIgnoreCase(args[0])) {
                    ScanService service = new ScanService();
                    ConsoleMenu menu = new ConsoleMenu(service);
                    menu.runDemoMode();
                    return;
                }
            }

            ScanService scanService = new ScanService();
            ConsoleMenu consoleMenu = new ConsoleMenu(scanService);
            consoleMenu.start();
        } catch (Exception e) {
            System.err.println(AnsiPalette.RED
                    + "Unexpected application error: " + e.getMessage()
                    + AnsiPalette.RESET);
        }
    }
}
