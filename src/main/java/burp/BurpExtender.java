package burp;

import lombok.val;

import java.io.PrintWriter;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.net.URL;

import burp.*;

public class BurpExtender implements IBurpExtender, IScannerCheck {
    private static final String EXTENSION_NAME = "Burp Security Headers Checker - Stishy";
    private static final String EXTENSION_VERSION = "1.2.0";

    private IBurpExtenderCallbacks burpExtenderCallbacks;
    private IExtensionHelpers burpExtensionHelpers;

    // Maintain a global list to store reported issues
    private List<String> reportedIssues = new ArrayList<>();

    @Override
    public void registerExtenderCallbacks(final IBurpExtenderCallbacks callbacks) {
        this.burpExtenderCallbacks = callbacks;
        this.burpExtensionHelpers = callbacks.getHelpers();

        callbacks.setExtensionName(EXTENSION_NAME);
        callbacks.registerScannerCheck(this);

        PrintWriter stdout = new PrintWriter(callbacks.getStdout(), true);
        stdout.println(EXTENSION_NAME + " version: " + EXTENSION_VERSION + " has been loaded");
    }

    @Override
    public List<IScanIssue> doPassiveScan(IHttpRequestResponse baseRequestResponse) {
        return checkResponseSecurityHeaders(baseRequestResponse);
    }

    @Override
    public List<IScanIssue> doActiveScan(IHttpRequestResponse baseRequestResponse, IScannerInsertionPoint insertionPoint) {
        return Collections.emptyList();
    }

    @Override
    public int consolidateDuplicateIssues(IScanIssue existingIssue, IScanIssue newIssue) {
        if (existingIssue.getIssueName().equalsIgnoreCase(newIssue.getIssueName()))
            return -1; // Return old issue
        else return 0;
    }

    private String getPathData(String url) {
        try {
            URL parsedUrl = new URL(url);
            String path = parsedUrl.getPath();
            return path;
        } catch (java.net.MalformedURLException e) {
            e.printStackTrace();
            return null;
        }
    }

    private List<IScanIssue> checkResponseSecurityHeaders(IHttpRequestResponse baseRequestResponse) {
        val response = baseRequestResponse.getResponse();
        val responseInfo = this.burpExtensionHelpers.analyzeResponse(response);

        val scanIssuesList = new ArrayList<IScanIssue>();

        for (CheckedSecurityHeadersEnum headerToCheck : CheckedSecurityHeadersEnum.values()) {
            boolean containsCheckedHeader = false;

            for (String responseHeader : responseInfo.getHeaders()) {
                if (responseHeader.toLowerCase().contains(headerToCheck.getHeaderName().toLowerCase())) {
                    containsCheckedHeader = true;
                    break;
                }
            }

            if (!containsCheckedHeader) {
                // Create a unique identifier for the issue based on the header and URL
                String issueIdentifier = headerToCheck.getHeaderName() + this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl().toString();

                // Check if the issue has already been reported
                if (!reportedIssues.contains(issueIdentifier)) {
                    // If not reported, add to the list and create a new issue
                    reportedIssues.add(issueIdentifier);
                    val missingHeadersScanIssue = createNewScannerIssue(responseInfo.getStatusCode(), headerToCheck, baseRequestResponse, false); 
                    scanIssuesList.add(missingHeadersScanIssue);
                } else {
                    // If the issue has already been reported, create a new issue but mark the boolean as true
                    val missingHeadersScanIssue = createNewScannerIssue(responseInfo.getStatusCode(), headerToCheck, baseRequestResponse, true); 
                    scanIssuesList.add(missingHeadersScanIssue);
                }
            }
        }
        return scanIssuesList;
    }

    private MissingSecurityHeaderIssue createNewScannerIssue(int statusCode, CheckedSecurityHeadersEnum headerToCheck, IHttpRequestResponse baseRequestResponse, boolean repeat) {
        String issueName = "Missing Security Header: " + headerToCheck.getHeaderName(); // Removed unnecessary initialization

        // Extract protocol and host
        String protocol = "";
        String host = "";
        String path = "";

        if (baseRequestResponse != null) {
            protocol = this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl().getProtocol();
            host = this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl().getHost();
            String fullUrl = this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl().toString();
            path = getPathData(fullUrl);
        }

        try {
            // Create a URL object from protocol and host
            URL url = new URL(protocol + "://" + host);

            if (!repeat) {
                // Use the base URL instead of the full URL
                return new MissingSecurityHeaderIssue(
                    url,
                    issueName,
                    "No " + headerToCheck.getHeaderName() + " security header has been detected in the server responses. For the following paths:<ul><li>" + path + "</li></ul>",
                    baseRequestResponse != null ? new IHttpRequestResponse[]{this.burpExtenderCallbacks.applyMarkers(baseRequestResponse, null, null)} : null,
                    baseRequestResponse != null ? baseRequestResponse.getHttpService() : null
                );
            } else {
                return new MissingSecurityHeaderIssue(
                    this.burpExtensionHelpers.analyzeRequest(baseRequestResponse).getUrl(),
                    issueName,
                    "No " + headerToCheck.getHeaderName() + " security header has been detected in the server responses. For the following paths:<ul><li>" + path + "</li></ul>",
                    null,
                    baseRequestResponse.getHttpService()
                );
            }
        } catch (java.net.MalformedURLException e) {
            // Handle the MalformedURLException here
            e.printStackTrace(); // You can log the exception or take appropriate action
            return null; // Return null or handle the error as needed
        }
    }
}
