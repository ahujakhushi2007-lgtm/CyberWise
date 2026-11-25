package com.cyberwise.exception;

/**
 * Checked exception thrown when a user enters an unsupported menu option.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 2A):</b>
 * Checked Custom Exceptions, Console Input Validation.</p>
 */
public class UnknownMenuOptionException extends CyberWiseException {

    private final String enteredChoice;

    public UnknownMenuOptionException(String enteredChoice) {
        super("Invalid menu option '" + enteredChoice + "'. Please choose a valid option from the menu.",
              "ERR_MENU_OPTION");
        this.enteredChoice = enteredChoice;
    }

    public String getEnteredChoice() {
        return this.enteredChoice;
    }
}
