# TRELLIX EDR Integrations

This is a collection of different TRELLIX EDR integration scripts. 

These scripts are intended to be a guideline and not supported by Trellix , if you help integrating scripts with EDR reach out to Trellix Professional services


## Client Credentials

To authenticate against the TRELLIX EDR API, generate client credentials using the Trellix Client Credentials portal:

- URL: https://uam.ui.trellix.com/clientcreds.html

High-level steps:
- Open the URL and sign in with your Trellix account
- Create a new client for EDR and grant the required scopes
- Copy and securely store the Client ID and Client Secret
- Use these values with the scripts in this repository

Note: The X-API-KEY used by EDR v2 endpoints is managed separately by your tenant administrator or Trellix support.

## Sample Scripts 

[TRELLIX EDR Action History](action-history):
This is a script to retrieve the action history from TRELLIX EDR.

<!-- [TRELLIX EDR Activity Feeds Script](activity-feeds): 
This is a script to consume activity feeds from TRELLIX EDR.
The script contains various modules to ingest trace data into e.g. ServiceNow, TheHive, Syslog or Email. -->

[TRELLIX EDR Device Search](device-search):
This is a script to query the device search in TRELLIX EDR.

[TRELLIX EDR Real-Time-Search and Reaction Script](real-time-search-reaction): 
This is a collections of scripts that will start RTS for hashes or process and provides the ability to execute reactions.

[TRELLIX EDR Threats](threats-monitoring):
This is a script to retrieve the threat detections from TRELLIX EDR (Monitoring Dashboard).
