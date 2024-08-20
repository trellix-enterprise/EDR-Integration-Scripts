# TRELLIX EDR Integrations

This is a collection of different TRELLIX EDR integration scripts. 

These scripts are intended to be a guideline and not supported by Trellix , if you help integrating scripts with EDR reach out to Trellix Professional services


## Client Credential Generator

To authenticate against the TRELLIX EDR API, client credentials need to be generated with the [TRELLIX EDR Credential Generator](trellix_edr_creds_generator.py) first.

1. Log on to TRELLIX EPO Console using your credentials
2. Go to "Appliance and Server Registration" page from the menu
   ![1](https://github.trellix.com/storage/user/3896/files/ba51cdf8-b73d-4ca3-99b0-95d15e8affb7)
3. Click on "Add" button
4. Choose client type "TRELLIX Endpoint Detection and Response"
5. Enter number of clients (1)


   ![2](https://github.trellix.com/storage/user/3896/files/9695f58c-8729-48ed-aef0-dee2d4c43387)

6. Click on the "Save" button
7. Copy the "Token" value from the table under the section "TRELLIX Endpoint Detection and Response"

   ![3](https://github.trellix.com/storage/user/3896/files/36c5b6c2-231f-49a8-a8db-b88a5c97e0f2)

8. Pass the token value as the input parameter to the [trellix_edr_creds_generator.py](trellix_edr_creds_generator.py) script
9. The script will generate the client_id, client_secret and print on the output console / writes the output to a file (optional)
10. Use the client_id, client_secret for authentication against the TRELLIX EDR API

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
