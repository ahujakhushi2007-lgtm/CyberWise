package com.cyberwise.concurrency;

/**
 * Animated terminal radar scanner using a background Daemon Thread (Lectures 26-29).
 */
public class RadarProgressAnimator implements Runnable {

    private volatile boolean running = true;
    private final String taskLabel;

    public RadarProgressAnimator(String taskLabel) {
        this.taskLabel = taskLabel;
    }

    public void stop() {
        this.running = false;
    }

    @Override
    public void run() {
        String[] frames = {"⠋", "⠙", "⠹", "⠸", "⠼", "⠴", "⠦", "⠧", "⠇", "⠏"};
        int i = 0;
        while (running) {
            System.out.print("\r\u001B[36m" + frames[i % frames.length] + " " + taskLabel + "...\u001B[0m");
            System.out.flush();
            i++;
            try {
                Thread.sleep(80); // TIMED_WAITING state
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                break;
            }
        }
        System.out.print("\r" + " ".repeat(taskLabel.length() + 15) + "\r");
        System.out.flush();
    }

    public static RadarProgressAnimator startAnimation(String taskLabel) {
        RadarProgressAnimator animator = new RadarProgressAnimator(taskLabel);
        Thread t = new Thread(animator, "RadarAnimatorThread");
        t.setDaemon(true); // Daemon thread terminates when user program exits (Lecture 28-29)
        t.start();
        return animator;
    }
}

