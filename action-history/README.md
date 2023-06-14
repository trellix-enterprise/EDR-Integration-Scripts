# MVISION EDR Action History

This is a script to retrieve the action history from MVISION EDR. 

The script requires tenant_region, client_id , client_secret and api key to pull the action history. 
Client_ID and Client_Secrets can get generated with the [trellix_edr_creds_generator.py](https://github.trellix.com/trellix-products/EDR-Integration-Scripts/blob/develop/trellix_edr_creds_generator.py) script posted in the main [repository](https://github.trellix.com/trellix-products/EDR-Integration-Scripts).

Usage: 

```sh
usage: python trellix_edr_edr_action_history.py  -C <CLIENT_ID> -S <CLIENT_SECRET> -K <X_API_KEY> -legacy <IS_LEGACY> -P <PROXY> -L <LIMIT> -LL <LOG_LEVEL>

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
  --is_legacy IS_LEGACY, -legacy IS_LEGACY
                        For Old Format
  --proxy {True,False}, -P {True,False}
                        Provide Proxy JSON in line 25 in trellix_edr_action_history.py
  --limit LIMIT, -L LIMIT
                        Set the maximum number of events returned
  --loglevel {INFO,DEBUG}, -LL {INFO,DEBUG}
                        Set Log Level

```

New Format Output:

```
{
  "jsonapi": {
    "version": "1"
  },
  "meta": {
    "totalResourceCount": 2
  },
  "data": [
    {
      "id": 56850,
      "type": "actions",
      "attributes": {
        "action": "removeFile",
        "investigationId": null,
        "creationDate": "2022-04-25T14:36:55.812+0000",
        "errorCode": null,
        "errorDescription": "",
        "hostsAffected": 1,
        "investigationName": null,
        "status": "COMPLETED",
        "threatId": null,
        "threatName": null,
        "userId": "nice@try.com"
      }
    },
    {
      "id": 56847,
      "type": "actions",
      "attributes": {
        "action": "killProcess",
        "investigationId": null,
        "creationDate": "2022-04-25T14:22:58.598+0000",
        "errorCode": null,
        "errorDescription": "",
        "hostsAffected": 1,
        "investigationName": null,
        "status": "COMPLETED",
        "threatId": null,
        "threatName": null,
        "userId": "nice@try.co"
      }
    }
  ]
}
```

Old Format Output:

```
{
    "currentItemCount": 2,
    "items":
    [
        {
            "action": "removeFile",
            "caseId": null,
            "creationDate": "2022-04-25T14:36:55.812+0000",
            "errorCode": null,
            "errorDescription": "",
            "hostsAffected": 1,
            "id": 56850,
            "investigationName": null,
            "status": "COMPLETED",
            "threatId": null,
            "threatName": null,
            "userId": "nice@try.com"
        },
        {
            "action": "killProcess",
            "caseId": null,
            "creationDate": "2022-04-25T14:22:58.598+0000",
            "errorCode": null,
            "errorDescription": "",
            "hostsAffected": 1,
            "id": 56847,
            "investigationName": null,
            "status": "COMPLETED",
            "threatId": null,
            "threatName": null,
            "userId": "nice@try.co"
        }
    ],
    "itemsPerPage": 2,
    "startIndex": 0,
    "totalItems": 60
}
```