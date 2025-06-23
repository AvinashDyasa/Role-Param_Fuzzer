Role Parameter Fuzzer – Burp Suite Extension
Overview
Role Parameter Fuzzer is a Burp Suite extension built with Jython to help security testers identify parameter manipulation and broken access control (BAC) issues in web applications. It’s designed to support advanced fuzzing and privilege escalation testing during security assessments.

Features
Parameter Fuzzing
Multi-parameter support
Automatically detects and fuzzes:

URL parameters

Form parameters

JSON keys
Custom payloads can be added as needed.

JSON-aware fuzzing
Parses nested JSON structures and allows you to target keys at any depth.

Payload management
Includes common payloads (e.g., SQL injection, null bytes, path traversal). You can also import your own payload lists.

Broken Access Control Testing
Role-based testing
Set up multiple user roles with custom headers to check for horizontal and vertical privilege escalation.

Header manipulation
Supports modifying authorization headers, session cookies, and other custom authentication headers.

Per-host configuration
Keep separate BAC settings for each target — useful when testing multiple applications.

Testing Features
Multi-tab interface
Run multiple tests at once, each with its own payloads and history.

Request/response history
Tracks all requests, with navigation and highlighting to make analysis easier.

Export & reporting
Export results, merge data between tabs, and save/load configurations.

Screenshot support
Capture in-tool screenshots for documenting findings.

Integration & Workflow
Right-click integration
Easily send requests to the extension from Burp’s interface.

Session persistence
Automatically saves your configs and restores them after restarting Burp.

Live parameter detection
Pulls parameters directly from intercepted requests for immediate fuzzing.

Installation
Prerequisites
Download the Jython standalone JAR:
https://www.jython.org/download.html
Use version: jython-standalone-2.7.3.jar

Save the JAR file somewhere permanent.

Set Up Jython in Burp
Open Burp Suite Professional

Go to: Extensions → Settings → Python Environment

Click Select file..., and choose your jython-standalone-2.7.3.jar

Save the configuration

Install the Extension
In Burp, go to Extensions → Installed

Click Add

Set extension type to Python

Select the Role_Param-Fuzzer.py file

Proceed through the setup and ensure there are no errors

Once installed, you should see a Param Fuzzer tab in Burp

Verify Setup
Right-click on any request (in Proxy, Repeater, etc.)

You should see a Send to Param Fuzzer option in the menu

Usage
Fuzzing Parameters
Right-click a request → Send to Param Fuzzer

Set your payloads in the Inspector panel

Click Attack to begin fuzzing

BAC Testing
Go to the BAC Check tab

Configure user roles with the appropriate headers

Click Access Check to test for access control flaws

All configurations and session data are saved automatically. Project-specific settings are supported for consistent use across different assessments.
