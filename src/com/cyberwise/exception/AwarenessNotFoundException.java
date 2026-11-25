package com.cyberwise.exception;

/**
 * Checked exception thrown when a requested scam awareness article ID does not exist.
 *
 * <p><b>Syllabus Topics Demonstrated (Unit 2A):</b>
 * Checked Custom Exceptions and Exception Propagation.</p>
 */
public class AwarenessNotFoundException extends CyberWiseException {

    private final String topicKey;

    public AwarenessNotFoundException(String topicKey) {
        super("No awareness article found for key: '" + topicKey + "'.", "ERR_AWARENESS_NOT_FOUND");
        this.topicKey = topicKey;
    }

    public String getTopicKey() {
        return this.topicKey;
    }
}
