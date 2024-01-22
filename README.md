# Burp Security Headers Checker
Super simple Burp Suite extension adding passive scanner checks for missing security headers in server responses. Adjusted the code to only report the issue once if mulitples web pages have missing X-Frame-Options. The issue will only report once at the base URL and not the subpage.

Headers checked:
* Content-Security-Policy (CSP)
* Feature-Policy
* Strict-Transport-Security (HSTS)
* X-Frame-Options
* X-Content-Type-Options
* Referrer-Policy

Removed Headers:
* X-XSS-Protection
### Building

To build release JAR with all dependencies (by using com.github.johnrengelman.shadow Gradle plugin) execute the command below from project root directory:
```./gradlew clean shadowJar```
