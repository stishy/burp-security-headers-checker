# Burp Security Headers Checker
Super simple Burp Suite extension adding passive scanner checks for missing security headers in server responses. Adjusted the code to only report the issue once with the request and response then for any pages thereafter record the path but drop the request and response to minimize evidence for report generation. The idea is most of data in the request and response is useless for the enduser as long as they see one example and have the path to the other pages they will be able to action on the output. Additionally the 400, 500 status pages with different findings was just merged with the same findings to keep the same naming convention. 

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
