@echo off
set TEMPDIR=C:\Users\PAD-MA~1\AppData\Local\Temp\secureops-fingerprint-test5
mkdir "%TEMPDIR%"
nmap -sV --version-light --top-ports 75 -T4 --max-retries 0 --host-timeout 20s -oX "%TEMPDIR%\fingerprint-172-16-2-3.xml" 172.16.2.3