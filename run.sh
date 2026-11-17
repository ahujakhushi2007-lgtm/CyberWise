#!/usr/bin/env bash
# CyberWise - Java Terminal Application Launcher
set -e

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"
cd "$DIR"

# Resolve JAVA_HOME if not set (macOS / Linux helper)
if [ -z "$JAVA_HOME" ]; then
    if [ -d "/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home" ]; then
        export JAVA_HOME="/Library/Java/JavaVirtualMachines/jdk-21.jdk/Contents/Home"
    elif [ -d "/opt/homebrew/opt/openjdk" ]; then
        export JAVA_HOME="/opt/homebrew/opt/openjdk"
    elif command -v /usr/libexec/java_home >/dev/null 2>&1; then
        export JAVA_HOME="$(/usr/libexec/java_home 2>/dev/null || true)"
    fi
fi

if [ -n "$JAVA_HOME" ] && [ -x "$JAVA_HOME/bin/java" ]; then
    JAVA_CMD="$JAVA_HOME/bin/java"
    JAVAC_CMD="$JAVA_HOME/bin/javac"
else
    JAVA_CMD="java"
    JAVAC_CMD="javac"
fi

echo "Compiling CyberWise Java Core..."
mkdir -p bin
$JAVAC_CMD -d bin $(find src -name "*.java")

echo "Starting CyberWise Terminal System..."
$JAVA_CMD -cp bin com.cyberwise.Main
