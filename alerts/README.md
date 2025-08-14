# Trellix EDR Alerts Collection Script - Customer Handover Guide

## Table of Contents
1. [Overview](#overview)
2. [Recent Updates](#recent-updates)
3. [Prerequisites](#prerequisites)
4. [Installation Guide](#installation-guide)
5. [Configuration](#configuration)
6. [Running the Script](#running-the-script)
7. [Monitoring and Maintenance](#monitoring-and-maintenance)
8. [Troubleshooting](#troubleshooting)
9. [API Environment Configuration](#api-environment-configuration)
10. [Support Information](#support-information)

---

## Recent Updates

### Version Updates - August 2025

**Major Changes:**
1. **Default IAM Issuer Changed**: The default authentication endpoint is now `auth.trellix.com`
2. **Simplified Authentication**: Removed the `audience` parameter from authentication requests for cleaner integration
3. **Dual IAM Support**: Added configurable support for both `auth.trellix.com` and `iam.cloud.trellix.com` environments
4. **Streamlined Authentication Scope**: Simplified to use only `soc.act.tg` scope for both IAM environments
5. **Syslog Forwarding (NEW)**: Optional forwarding of each processed alert JSON to a remote syslog server (UDP) when `SYSLOG_IP` and `SYSLOG_PORT` are set

**Migration Impact:**
- **Existing Deployments**: No action required - the script automatically uses the new default endpoint
- **Custom Configurations**: If you explicitly set `IAM_ISSUER=cloud`, your configuration remains unchanged
- **Credentials**: Your existing EDR credentials continue to work with the new endpoints
- **Optional Syslog**: Add the new env vars if you want central log collection of raw alerts

**Configuration Changes:**
- New environment variables: `IAM_ISSUER`, `SYSLOG_IP`, `SYSLOG_PORT`
- Updated default authentication URL: `auth.trellix.com/auth/realms/IAM/protocol/openid-connect`
- Simplified authentication scope: Both IAM environments now use only `soc.act.tg` scope

**Benefits:**
- Improved authentication reliability
- Simplified configuration process
- Better compatibility with latest Trellix EDR environments
- Streamlined customer onboarding
- Centralized alert forwarding (syslog)

---

## Overview

The Trellix EDR Alerts Collection Script is designed to continuously retrieve security alerts from the Trellix EDR (Endpoint Detection and Response) platform via REST API. The script runs in an infinite loop, collecting new alerts every specified interval and storing them locally for further processing or integration with external systems.

### Key Features
- **Continuous Monitoring**: Runs indefinitely, checking for new alerts at configurable intervals
- **Intelligent Caching**: Maintains state to avoid duplicate alert processing
- **Flexible Logging**: Configurable logging levels with automatic log rotation
- **Individual Alert Storage**: Option to save each alert as a separate JSON file
- **Rate Limit Handling**: Automatic retry logic for API rate limiting
- **Token Management**: Automatic authentication token refresh every execution cycle
- **Optional Syslog Forwarding**: Sends full JSON of each alert to remote syslog if configured

---

## Prerequisites

### System Requirements
- **Operating System**: Linux, Windows, or macOS
- **Python Version**: Python 3.6 or higher
- **Network Access**: HTTPS connectivity to Trellix cloud services (and UDP/514 to syslog target if using syslog)
- **Disk Space**: Minimum 1GB for logs and cache files

### Python Dependencies
Install the required Python packages using pip:

```bash
pip install requests python-dotenv pytz python-dateutil
```

### Trellix API Credentials
You must obtain the following credentials from the Trellix Client Credentials portal:

- URL: https://uam.ui.trellix.com/clientcreds.html

1. **EDR Client ID**: Client_ID
2. **EDR Client Secret**: Secret 
3. **X-API-KEY**: API key for EDR v2 endpoints

**Required API Scopes:**
```
soc.act.tg
```

---

## Installation Guide

### Step 1: Create Installation Directory
```bash
sudo mkdir -p /opt/trellix-edr
sudo chown $USER:$USER /opt/trellix-edr
cd /opt/trellix-edr
```

### Step 2: Download Script
Place the `trellix_edr_alerts.py` script in the installation directory.

### Step 3: Create Required Directories
```bash
# Create directories for logs, cache, and alerts
sudo mkdir -p /var/log/trellix-edr
sudo mkdir -p /var/cache/trellix-edr
sudo mkdir -p /var/alerts/trellix-edr

# Set appropriate permissions
sudo chown $USER:$USER /var/log/trellix-edr
sudo chown $USER:$USER /var/cache/trellix-edr
sudo chown $USER:$USER /var/alerts/trellix-edr

sudo chmod 755 /var/log/trellix-edr
sudo chmod 755 /var/cache/trellix-edr
sudo chmod 755 /var/alerts/trellix-edr
```

### Step 4: Install Python Dependencies
```bash
pip3 install requests python-dotenv pytz python-dateutil
```

---

## Configuration

### Environment Variables

Create a `.env` file in the script directory or set system environment variables:

#### Required Variables
```bash
# Trellix EDR API Credentials
EDR_CLIENT_ID=your_client_id_here
EDR_CLIENT_SECRET=your_client_secret_here
X_API_KEY=your_api_key_here

# Directory Configuration
CACHE_DIR=/var/cache/trellix-edr
LOG_DIR=/var/log/trellix-edr
```

#### Optional Variables
```bash
# Alert File Storage (set to 'true' to save individual alert files)
ALERT_LOG=true
ALERT_DIR=/var/alerts/trellix-edr

# Script Behavior
INTERVAL=300              # Run interval in seconds (default: 5 minutes)
INITIAL_PULL=1           # Days to pull on first run (default: 1 day)
LOG_LEVEL=INFO           # Logging level: DEBUG, INFO, WARNING, ERROR

# Network Configuration (if behind proxy)
PROXY=http://proxy.company.com:8080

# IAM Issuer (default 'auth'; set to 'cloud' for legacy endpoint)
IAM_ISSUER=auth

# Syslog Forwarding (optional)
SYSLOG_IP=10.10.10.10
SYSLOG_PORT=514
```

### Sample .env File
```env
# Trellix EDR Configuration
EDR_CLIENT_ID=pmUjMkBxeR4vc_RIG-dfgtyu
EDR_CLIENT_SECRET=vrY0g26v0iAhPKhzYg0sdg4gh
X_API_KEY=VCt5WElheGJ2a2Y5ejBvWXVVWDlQSXB6Q0cvTzJPQUdlQmtsWGVXZG4rUTp1c45sghjr

# Directory Configuration
CACHE_DIR=/var/cache/trellix-edr
LOG_DIR=/var/log/trellix-edr
ALERT_DIR=/var/alerts/trellix-edr

# Script Configuration
ALERT_LOG=true
LOG_LEVEL=INFO
INTERVAL=600
INITIAL_PULL=7
IAM_ISSUER=auth
SYSLOG_IP=10.10.10.10
SYSLOG_PORT=514
```

---

## Running the Script

### Manual Execution

#### Test Run (Single Execution)
```bash
cd /opt/trellix-edr
python3 trellix_edr_alerts.py
```

#### Production Run (Continuous)
The script runs continuously by default. To run in background:
```bash
nohup python3 trellix_edr_alerts.py > /dev/null 2>&1 &
```

### Running as a System Service (Recommended)

#### Create Systemd Service File
Create `/etc/systemd/system/trellix-edr-alerts.service`:

```ini
[Unit]
Description=Trellix EDR Alerts Collector
Documentation=https://developer.manage.trellix.com/
After=network.target
Wants=network-online.target

[Service]
Type=simple
User=trellix
Group=trellix
WorkingDirectory=/opt/trellix-edr
Environment=EDR_CLIENT_ID=your_client_id
Environment=EDR_CLIENT_SECRET=your_client_secret
Environment=X_API_KEY=your_api_key
Environment=CACHE_DIR=/var/cache/trellix-edr
Environment=LOG_DIR=/var/log/trellix-edr
Environment=ALERT_DIR=/var/alerts/trellix-edr
Environment=ALERT_LOG=true
Environment=LOG_LEVEL=INFO
Environment=INTERVAL=300
Environment=INITIAL_PULL=1
Environment=IAM_ISSUER=auth
Environment=SYSLOG_IP=10.10.10.10
Environment=SYSLOG_PORT=514
ExecStart=/usr/bin/python3 /opt/trellix-edr/trellix_edr_alerts.py
Restart=always
RestartSec=30
StandardOutput=journal
StandardError=journal

[Install]
WantedBy=multi-user.target
```

#### Enable and Start Service
```bash
# Reload systemd configuration
sudo systemctl daemon-reload

# Enable service to start on boot
sudo systemctl enable trellix-edr-alerts

# Start the service
sudo systemctl start trellix-edr-alerts

# Check service status
sudo systemctl status trellix-edr-alerts
```

#### Service Management Commands
```bash
# Start service
sudo systemctl start trellix-edr-alerts

# Stop service
sudo systemctl stop trellix-edr-alerts

# Restart service
sudo systemctl restart trellix-edr-alerts

# View service logs
sudo journalctl -u trellix-edr-alerts -f

# Check service status
sudo systemctl status trellix-edr-alerts
```

---

## Monitoring and Maintenance

### Log Files

#### Application Logs
- **Location**: `${LOG_DIR}/mvedr_logger_alerts.log`
- **Rotation**: Automatic at 25MB, keeps 5 backup files
- **Format**: `YYYY-MM-DD HH:MM:SS,mmm;LEVEL;MESSAGE`

#### Cache Files
- **Location**: `${CACHE_DIR}/cache_alerts.log`
- **Purpose**: Stores timestamp of last processed alert
- **Format**: ISO 8601 datetime string

#### Individual Alert Files
- **Location**: `${ALERT_DIR}/*.log` (when ALERT_LOG=true)
- **Format**: `YYYYMMDDHHMMSS-RuleId.log`
- **Content**: Complete JSON alert data

#### Syslog Forwarding
- **Protocol**: UDP (default syslog)
- **Payload**: Raw JSON string of each alert
- **Use Case**: Centralized SIEM ingestion or long-term storage

### Monitoring Script Health

#### Check Service Status
```bash
sudo systemctl status trellix-edr-alerts
```

#### Monitor Logs in Real-time
```bash
tail -f /var/log/trellix-edr/mvedr_logger_alerts.log
```

#### Check for Errors
```bash
grep ERROR /var/log/trellix-edr/mvedr_logger_alerts.log
```

#### Monitor API Call Statistics
Look for log entries like:
```
2025-08-05 10:30:45,123;INFO;total API resource count 3
```

### Performance Metrics

#### Key Performance Indicators
- **API Calls per Cycle**: Number of API requests made per execution
- **Alerts Processed**: Number of new alerts retrieved
- **Execution Time**: Time taken for each cycle
- **Error Rate**: Frequency of authentication or API errors

#### Log Analysis Examples
```bash
# Count total API calls in last 24 hours
grep "total API resource count" /var/log/trellix-edr/mvedr_logger_alerts.log | tail -288

# Check authentication success rate
grep "AUTHENTICATION" /var/log/trellix-edr/mvedr_logger_alerts.log | tail -20

# Monitor alert processing
grep "Retrieved new MVISION EDR Alert" /var/log/trellix-edr/mvedr_logger_alerts.log | tail -50
```

---

## Troubleshooting

### Common Issues and Solutions

#### 1. Authentication Errors
**Symptoms:**
```
ERROR;Error in retrieving edr.auth(). Error: 401 - {"error":"invalid_client"}
```

**Solutions:**
- Verify EDR_CLIENT_ID and EDR_CLIENT_SECRET are correct
- Check API scopes with Trellix administrator
- Ensure credentials haven't expired

#### 2. Permission Errors
**Symptoms:**
```
ERROR;[Errno 13] Permission denied: '/var/log/trellix-edr/mvedr_logger_alerts.log'
```

**Solutions:**
```bash
# Fix directory permissions
sudo chown -R $USER:$USER /var/log/trellix-edr
sudo chown -R $USER:$USER /var/cache/trellix-edr
sudo chown -R $USER:$USER /var/alerts/trellix-edr
```

#### 3. Network/Proxy Issues
**Symptoms:**
```
ERROR;Connection timeout or proxy errors
```

**Solutions:**
- Configure PROXY environment variable if behind corporate firewall
- Verify network connectivity to Trellix endpoints
- Check firewall rules for HTTPS traffic

#### 4. Date Format Errors
**Symptoms:**
```
ERROR;time data '2025-08-05T06:21:41.707+00:00' does not match format
```

**Solutions:**
- Script automatically handles multiple date formats
- If issues persist, check for API response format changes
- Enable DEBUG logging to see raw API responses

#### 5. Rate Limiting
**Symptoms:**
```
DEBUG;Rate Limit Exceed in Alerts Api, retrying after 300 sec
```

**Solutions:**
- Script automatically handles rate limiting with exponential backoff
- Consider increasing INTERVAL to reduce API call frequency
- Monitor API usage patterns

#### 6. Syslog Not Receiving Alerts
**Symptoms:**
- No events appear on the remote syslog server

**Solutions:**
- Verify UDP connectivity to SYSLOG_IP:SYSLOG_PORT
- Ensure firewall allows outbound UDP 514 (or custom port)
- Confirm environment variables are set in service definition
- Check for "Failed to configure syslog handler" errors at startup

### Debug Mode

To enable detailed debugging:

```bash
export LOG_LEVEL=DEBUG
```

Or modify the .env file:
```env
LOG_LEVEL=DEBUG
```

Debug mode provides:
- Detailed API request/response information
- Authentication token details
- Cache file operations
- Individual alert processing steps

### Emergency Procedures

#### Stop Script Immediately
```bash
sudo systemctl stop trellix-edr-alerts
```

#### Reset Cache (Force Full Resync)
```bash
sudo rm /var/cache/trellix-edr/cache_alerts.log
```

#### Clear All Logs
```bash
sudo rm /var/log/trellix-edr/mvedr_logger_alerts.log*
```

---

## API Environment Configuration

### Dual IAM Issuer Support
The script supports two authentication environments through the `IAM_ISSUER` environment variable:

#### Default Configuration (auth.trellix.com)
```python
# Default when IAM_ISSUER=auth or not set
self.iam_url = 'auth.trellix.com/auth/realms/IAM/protocol/openid-connect'
self.base_url = 'api.manage.trellix.com'
```

**Authentication Scope**: `soc.act.tg`

#### Alternative Configuration (iam.cloud.trellix.com)
```python
# When IAM_ISSUER=cloud
self.iam_url = 'iam.cloud.trellix.com/iam/v1.0'
self.base_url = 'api.manage.trellix.com'
```

**Authentication Scope**: `soc.act.tg`

### Configuration Examples

#### Using Default auth.trellix.com (Recommended)
```bash
# In .env file or environment
EDR_CLIENT_ID=your_client_id
EDR_CLIENT_SECRET=your_client_secret
X_API_KEY=your_api_key
IAM_ISSUER=auth  # or omit entirely for default
```

#### Using iam.cloud.trellix.com
```bash
# In .env file or environment
EDR_CLIENT_ID=your_client_id
EDR_CLIENT_SECRET=your_client_secret
X_API_KEY=your_api_key
IAM_ISSUER=cloud
```

**Important Notes:**
- The default IAM issuer is now `auth.trellix.com`
- Different IAM issuers may require different credentials
- Contact your Trellix administrator to confirm which environment to use
- Test thoroughly with your specific credentials before production deployment

### API Endpoints Used

The script interacts with the following Trellix EDR API endpoints:

1. **Authentication (Default)**: `POST https://auth.trellix.com/auth/realms/IAM/protocol/openid-connect/token`
2. **Authentication (Alternative)**: `POST https://iam.cloud.trellix.com/iam/v1.0/token`
3. **Alerts Retrieval**: `GET https://api.manage.trellix.com/edr/v2/alerts`

### API Parameters

#### Alert Query Parameters
- **filter**: Severity levels (s1, s2, s3, s4, s5)
- **from**: Epoch timestamp for filtering alerts since last run
- **page[limit]**: Number of alerts per page (default: 1000)
- **page[offset]**: Pagination offset

#### Authentication Scopes by Environment

**Both Environments (auth.trellix.com and iam.cloud.trellix.com)**:
```
soc.act.tg
```

---

## Support Information

### Script Information
- **Type**: Guideline script (not officially supported by Trellix)
- **Purpose**: Integration example for Trellix EDR alerts collection
- **Maintenance**: Customer responsibility

### API Documentation
- **Developer Portal**: https://developer.manage.trellix.com/
- **EDR API Reference**: https://developer.manage.trellix.com/public/mvision/apis/threats
- **Authentication Guide**: Available in Trellix developer documentation


### Script Limitations
- No built-in data transformation or enrichment
- Limited to alert retrieval (no threat context or additional metadata)
- No built-in integration with external systems (SIEM, SOAR, etc.)
- Basic error handling and retry logic

### Recommended Enhancements
For production deployments, consider implementing:
- **Data Transformation**: Custom alert formatting for target systems
- **External Integrations**: Direct SIEM/SOAR connectors
- **Advanced Monitoring**: Health checks and alerting
- **Data Validation**: Alert schema validation and quality checks
- **Backup and Recovery**: Cache backup and disaster recovery procedures

---

## Appendix

### Environment Variables Reference

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| EDR_CLIENT_ID | Yes | None | OAuth2 client identifier |
| EDR_CLIENT_SECRET | Yes | None | OAuth2 client secret |
| X_API_KEY | Yes | None | API key for EDR v2 endpoints |
| CACHE_DIR | Yes | None | Directory for cache files |
| LOG_DIR | Yes | None | Directory for log files |
| ALERT_LOG | No | False | Enable individual alert file storage |
| ALERT_DIR | No | None | Directory for individual alert files |
| INTERVAL | No | 300 | Execution interval in seconds |
| INITIAL_PULL | No | 1 | Days to pull on first run |
| LOG_LEVEL | No | INFO | Logging verbosity level |
| PROXY | No | None | HTTP proxy URL |
| IAM_ISSUER | No | auth | IAM authentication issuer ('auth' or 'cloud') |
| SYSLOG_IP | No | None | Remote syslog server IP (for alert forwarding) |
| SYSLOG_PORT | No | 514 | Remote syslog server port (for alert forwarding) |

### File Structure
```
/opt/trellix-edr/
├── trellix_edr_alerts.py      # Main script
├── .env                       # Environment configuration
└── README.md                  # This documentation

/var/log/trellix-edr/
├── mvedr_logger_alerts.log    # Current log file
├── mvedr_logger_alerts.log.1  # Rotated log files
├── mvedr_logger_alerts.log.2
└── ...

/var/cache/trellix-edr/
└── cache_alerts.log           # Last processed timestamp

/var/alerts/trellix-edr/       # Individual alert files (optional)
├── 20250805103045-RuleId1.log
├── 20250805103046-RuleId2.log
└── ...
```

### Sample Alert Output Format
```json
{
    "type": "alerts",
    "id": "01be29b2-0809-1170-0063-5c032b46c226.d598006ee3cb8409e4a574c5d2de303f",
    "attributes": {
        "Severity": "s3",
        "Process_Integrity": "0.0",
        "Root_Trace_Id": "b12eebd9-5c92-4a66-b364-671fe2d2d034",
        "Related_Trace_Id": [
            "b12eebd9-5c92-4a66-b364-671fe2d2d034",
            "b7e730da-80e4-4981-8a1d-d42e23851a74"
        ],
        "Process_Sha256": "4d0f10e9510906e44e8662c586543ece577aff208fa20c42a445fd3a1ab34b5a",
        "Hash_Id": "nnHSGkIFtY4MZcH3+eiESg==",
        "Parents_Trace_Id": [
            "b12eebd9-5c92-4a66-b364-671fe2d2d034",
            "89d08e4b-8a9a-465b-ae32-eafa493cd13d",
            "00000000-0000-0000-0000-000000000000"
        ],
        "Detection_Tags": [
            "@ATA.Persistence",
            "@ATE.T1505.003",
            "@MSI._process_webshell"
        ],
        "Process_Path": "/tmp/bash",
        "CommandLine": "./httpd",
        "Rank": 210,
        "Pid": 43865,
        "Host_Name": "RHEL1",
        "DetectionDate": "2025-08-04T09:15:45.592+00:00",
        "ProcessName": "httpd",
        "Trace_Id": "64fdbf6e-4b5c-422a-b83a-988b0307ca8d",
        "MAGUID": "B3FABC6A-A0A5-11EC-34D1-005056997043",
        "Version": "undefined",
        "Process_Md5": "a3224781d8d30ebcdb7041f2fa918fd5",
        "Event_Date": "2025-08-04T04:05:16.000Z",
        "Host_OS": "linux",
        "Artifact": "Threat",
        "Parent_Trace_Id": "b12eebd9-5c92-4a66-b364-671fe2d2d034",
        "Score": 60,
        "User": {
            "domain": "",
            "name": "mcafee"
        },
        "Activity": "Threat Detected",
        "RuleId": "_process_webshell"
    }
}
---

**Document Version**: 1.0  
**Last Updated**: August 5, 2025  
**Script Version**: trellix_edr_alerts.py  
**Compatibility**: Trellix EDR API v2
