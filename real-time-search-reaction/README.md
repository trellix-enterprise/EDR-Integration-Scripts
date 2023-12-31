# MVISION EDR Real-Time-Search and Reactions

This is a collection of scripts to run Real-Time-Search and optional to execute reactions. 

The script requires client_id and client_secret and api key to execute real-time searches. 
Client_ID and Client_Secrets can get generated with the [trellix_edr_creds_generator.py](https://github.trellix.com/trellix-products/EDR-Integration-Scripts/blob/develop/trellix_edr_creds_generator.py) script posted in the main [repository](https://github.trellix.com/trellix-products/EDR-Integration-Scripts).

Search Hash Usage:
```
usage: Usage: python trellix_edr_search_hash.py -C <CLIENT_ID> -S <CLIENT_SECRET> -K <X_API_KEY> -H <HASH>

MVISION EDR Python API

arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                       [Depricated] MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --x_api_key X_API_Key, -K X_API_KEY
                        MVISION API Key
  --hash HASH, -H HASH
  --reaction {True,False}, -RE {True,False}
                        Delete Files that got identified.
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Specify log level.

```

Search Process Usage:

```
usage: Usage: python trellix_edr_search_process.py  -C <CLIENT_ID> -S <CLIENT_SECRET> -K <X_API_KEY> -PN <process name>

MVISION EDR Python API

arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        [Depricated]MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --x_api_key X_API_Key, -K X_API_KEY
                        MVISION API Key                        
  --process PROCESS, -PN PROCESS
  --reaction {True,False}, -RE {True,False}
                        Kill Process
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Specify log level

```

Search Filename Usage:

```
usage: Usage: python trellix_edr_search_filename.py  -C <CLIENT_ID> -S <CLIENT_SECRET> -K <X_API_KEY> -F <FILE>

MVISION EDR Python API

arguments:
  -h, --help            show this help message and exit
  --region {EU,US-W,US-E,SY,GOV}, -R {EU,US-W,US-E,SY,GOV}
                        [Depricated]MVISION EDR Tenant Location
  --client_id CLIENT_ID, -C CLIENT_ID
                        MVISION EDR Client ID
  --client_secret CLIENT_SECRET, -S CLIENT_SECRET
                        MVISION EDR Client Secret
  --x_api_key X_API_Key, -K X_API_KEY
                        MVISION API Key
  --file FILE, -F FILE
  --reaction {True,False}, -RE {True,False}
                        Delete Files that got identified.
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Specify log level.

```