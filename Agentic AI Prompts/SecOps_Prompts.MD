## SecOps Hunting

* Show me all failed login attempts from IP address
```
Show me all failed login attempts from IP addresses that have not previously authenticated successfully to this system within the past 30 days. Include the source IP, account name, and timestamp.
```

* Unusual traffic patterns
```
Identify unusual network traffic patterns, such as spikes in data transfer or connections to unfamiliar IP addresses in the past 30 days
```

* Suspicious Process Execution
```
Show me all processes launched from temp directories, user profile AppData in the last 7 days. Inlcude the process name, associated username, full commandline, and timestamp. Examine any suspicious behaviours - such as command line utilities - and enrich these indicators with gti. Provide the child processes should gti returns a verdict of suspicious or malicious. 
```

***