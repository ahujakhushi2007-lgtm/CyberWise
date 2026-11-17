@echo off
REM CyberWise - Java Terminal Application Launcher (Windows)
echo Compiling CyberWise Java Core...
if not exist "bin" mkdir bin
dir /s /b src\*.java > sources.txt
javac -d bin @sources.txt
del sources.txt

echo Starting CyberWise Terminal System...
java -cp bin com.cyberwise.Main
pause

