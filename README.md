# Yara-Scanner _MOD by Davide Bovio && Vincenzo Digilio :dagger: 

Do you want more hacking? :bow_and_arrow: https://thehackingquest.net/

NOTE: This Project is a mod of "yara-scanner" designed by iomoath, that introduce different new features. You can find the original project at the following link: https://github.com/iomoath/yara-scanner

:mag: You can find "Installing Instructions" | "Arguments" | "Usage Example" at --> https://github.com/iomoath/yara-scanner

YaraScanner is a simple threat hunting & IOC scanner tool. Yara rules based.

:atom: Yara-Scanner Features:

- Scan a single file. Attempt to find a pattern matching with given file.
- Scan a directory. Scan for file(s) in given directory path and attempt to find a pattern matching with Yara rules.
- Scan web access logs. By getting list of accessed file paths from access logs and attempt to find a pattern matching with Yara Rules.
- Auto fetch Yara rules from Neo23x0
- Flexibility, using custom Yara rules
- HTML scan reports
- Deliver reports by email
- Email alerts, when a pattern match is found
- Logging

:electron: What does this mod add to the original features?

- Added a field in the report with HOSTNAME and USERNAME :computer:
- Implemented a multithread for speeding up the scan. Now the script engages until the 60% of CPU :zap:
  - Added multithread in the "matchfile" routine
  - Added multithread in the "match" routine
  - NB: the max number of workers depends on the CPU core number engaged
- Now during the scan is possible to see the total number of files to be scanned and the current scan file number :abacus:
- Reworked the log, now it shows the complete file path :flashlight:
- Reworked the log, now if the script crashes the current results will be saved in the log file :label: 

Other changes :books: :

- Created a new yara_match.py module
- Routine "match" has been moved (from yara_scanner.py to yara_match.py)
- yara_match.py module:
  - "matchrule" has been splitted for rile analisys
  - "matchfile" has been splitted for file analisys



