#!/usr/bin/env python3
# Script to retrieve all alerts
# This is a script intended to be a guideline and not supported by Trellix , if you help integrating scripts with EDR reach out to Trellix Professional services

import sys
import requests
import time
import logging
import logging.handlers
import json
import os
import pytz

from datetime import datetime, timedelta
from dateutil import tz, parser as dateutil_parser
from dotenv import load_dotenv

load_dotenv(verbose=True)

total_api_counts = 0
date_pattern = '%Y-%m-%dT%H:%M:%SZ'
detection_date_pattern = '%Y-%m-%dT%H:%M:%S.%f%z'

# Helper to robustly parse ISO 8601 timestamps (handles both 'Z' and offsets like '+00:00')
def parse_iso_dt(value: str) -> datetime:
    try:
        return dateutil_parser.isoparse(value)
    except Exception:
        # Fallbacks for older/variant formats
        try:
            return datetime.strptime(value, date_pattern).replace(tzinfo=pytz.UTC)
        except Exception:
            # Best-effort final fallback (may still raise on some variants)
            return datetime.fromisoformat(value)

class EDR():
    
    def __init__(self):
        # Support for multiple IAM issuers
        if iam_issuer and iam_issuer.lower() == 'cloud':
            self.iam_url = 'iam.cloud.trellix.com/iam/v1.0'
        else:
            self.iam_url = 'auth.trellix.com/auth/realms/IAM/protocol/openid-connect'
        
        self.base_url='api.manage.trellix.com'

        self.session = requests.Session()

        if proxy is not None:
            self.session.proxies['https'] = proxy

        creds = (edr_client_id, edr_client_secret)

        self.pattern = '%Y-%m-%dT%H:%M:%S.%f'
        self.cache_fname = '{0}/cache_alerts.log'.format(cache_dir)
        if os.path.isfile(self.cache_fname):
            cache = open(self.cache_fname, 'r')
            cache_content = cache.read().strip()
            cache.close()
            try:
                last_detection = parse_iso_dt(cache_content)
            except Exception:
                # Preserve previous behavior in case of unexpected format
                last_detection = datetime.strptime(cache_content, detection_date_pattern)
            
            last_detection_utc = last_detection.replace(tzinfo=pytz.UTC) if last_detection.tzinfo is None else last_detection.astimezone(pytz.UTC)
            next_pull = last_detection_utc.astimezone(tz.tzlocal()) + timedelta(seconds=1)

            logger.debug('Cache exists. Last detection date UTC: {0}'.format(last_detection))
            logger.debug('Pulling newest alerts from: {0}'.format(next_pull))
            cache.close()
        else:
            logger.debug('Cache does not exists. Pulling data from last {0} days.'.format(initial_pull))
            next_pull = datetime.now() - timedelta(days=int(initial_pull))

        self.epoch_pull = str(datetime.timestamp(next_pull)*1000)[:13]
        logger.debug('New pulling date {0} - epoch {1}'.format(next_pull, self.epoch_pull))

        self.auth(creds)
        self.alert_limit = 1000
        global total_api_counts
        total_api_counts=0

    def auth(self, creds):
        try:
            # Configure payload based on IAM issuer
            if iam_issuer and iam_issuer.lower() == 'cloud':
                # Original IAM issuer (iam.cloud.trellix.com)
                payload = {
                    'scope': 'soc.act.tg',
                    'grant_type': 'client_credentials'
                }
            else:
                # New IAM issuer (auth.trellix.com) - now default
                payload = {
                    'scope': 'soc.act.tg',
                    'grant_type': 'client_credentials'
                }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)

            if res.ok:
                token = res.json()['access_token']
                self.session.headers = {'Authorization': 'Bearer {}'.format(token)}
                logger.debug('AUTHENTICATION: Successfully authenticated.')
            else:
                logger.error('Error in retrieving edr.auth(). Request url: {}'.format(res.url))
                logger.error('Error in retrieving edr.auth(). Request headers: {}'.format(res.request.headers))
                logger.error('Error in retrieving edr.auth(). Request body: {}'.format(res.request.body))
                raise Exception('Error in retrieving edr.auth(). Error: {0} - {1}'.format(str(res.status_code), res.text))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def get_alerts(self):
        try:
            global total_api_counts
            skip = 0
            tnextflag = True
            alerts_processed = 0

            filter_params = {}
            severities = ["s1", "s2", "s3", "s4", "s5"]
            filter_params['severities'] = severities
            headers = {
                'Content-Type': 'application/vnd.api+json',
                'x-api-key':x_api_key
                }

            while(tnextflag):
                res = self.session.get(
                    'https://{0}/edr/v2/alerts?filter={1}&from={2}&page[limit]={3}&page[offset]={4}'
                        .format(self.base_url, json.dumps(filter_params), self.epoch_pull, self.alert_limit, skip),headers=headers)

                if res.ok:
                    total_api_counts+=1
                    logger.debug("processing alerts API response")
                    res = res.json()
                    if 'links' in res and res['links']['next'] == None:
                        tnextflag = False
                    else:
                        skip = skip + self.alert_limit

                    if len(res['data']) > 0:
                        if os.path.isfile(self.cache_fname):
                            cache = open(self.cache_fname, 'r')
                            cache_content = cache.read().strip()
                            cache.close()
                            try:
                                last_detection = parse_iso_dt(cache_content)
                            except Exception:
                                last_detection = datetime.strptime(cache_content, detection_date_pattern)
                            
                            current_detection_str = res['data'][0]['attributes']['DetectionDate']
                            try:
                                current_detection = parse_iso_dt(current_detection_str)
                            except Exception:
                                current_detection = datetime.strptime(current_detection_str, detection_date_pattern)
                            
                            if last_detection < current_detection:
                                logger.debug('More recent detection timestamp detected. Updating cache.')
                                cache = open(self.cache_fname, 'w')
                                cache.write(res['data'][0]['attributes']['DetectionDate'])
                                cache.close()
                            else:
                                logger.debug('More recent detection timestamp in cache already saved.')
                        else:
                            cache = open(self.cache_fname, 'w')
                            cache.write(res['data'][0]['attributes']['DetectionDate'])
                            cache.close()

                        for alert in res['data']:
                            alerts_processed += 1
                            logger.debug(json.dumps(alert))
                            alert_name = alert['attributes'].get('RuleId', 'Unknown')
                            logger.info('Retrieved new MVISION EDR Alert. {0}'.format(alert_name))

                            if alerts_log and alerts_log.lower() == 'true':
                                if os.path.exists(alert_dir) is False:
                                    os.mkdir(alert_dir)

                                time_detect = alert['attributes']['DetectionDate']
                                try:
                                    ptime_detect = parse_iso_dt(time_detect)
                                except Exception:
                                    ptime_detect = datetime.strptime(time_detect, detection_date_pattern)
                                
                                alert_name = alert['attributes'].get('RuleId', 'Unknown')
                                filename = '{}-{}.log'.format(ptime_detect.strftime('%Y%m%d%H%M%S'), alert_name.replace("/", "-"))
                                file = open('{}/{}'.format(alert_dir, filename), 'w')
                                file.write(json.dumps(alert))
                                file.close()
                    else:
                        logger.debug('No new alerts identified. Exiting. {0}'.format(res))
                        tnextflag = False
                elif res.status_code==429:
                     retry_interval=self.get_retryinterval(res)
                     logger.debug('Rate Limit Exceed in Alerts Api, retrying after  {} sec'.format(retry_interval))
                     time.sleep(int(retry_interval))            
                else:
                    logger.error('Error in retrieving edr.get_alerts(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_alerts(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_alerts(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_alerts(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            logger.debug('Pulled total {0} Alerts.'.format(alerts_processed))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def get_retryinterval(self,response):
        logger.debug("\nResponse Header received:\n\n{}".format(response.headers))
        retry_val = "300"
        if 'Retry-After' in response.headers:
            retry_val = response.headers["Retry-After"]
            logger.debug('\nRetry interval set to {} secs. Sleeping...'.format(retry_val))
        else:
            logger.debug("\nRetry-after attribute is not present in response header..")
        return retry_val

if __name__ == '__main__':
    edr_client_id = os.getenv('EDR_CLIENT_ID')
    edr_client_secret = os.getenv('EDR_CLIENT_SECRET')

    interval = os.getenv('INTERVAL', "300") # Interval in seconds, 5 minutes
    initial_pull = os.getenv('INITIAL_PULL', "1") # In Days
    iam_issuer = os.getenv('IAM_ISSUER', 'auth') # 'cloud' or 'auth'

    proxy = os.getenv('PROXY')
    cache_dir = os.getenv('CACHE_DIR')

    log_level = os.getenv('LOG_LEVEL')
    log_dir = os.getenv('LOG_DIR')

    alerts_log = os.getenv('ALERT_LOG')
    alert_dir = os.getenv('ALERT_DIR')
    x_api_key=os.getenv('X_API_KEY')
    
    
    # setup logging
    logger = logging.getLogger('mvedr_logger')
    logger.setLevel(log_level)
    formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
    
    # setup the console logger
    console_handler = logging.StreamHandler()
    console_handler.setFormatter(formatter)
    logger.addHandler(console_handler)

    # setup the file logger
    if os.path.exists(log_dir) is False:
        os.mkdir(log_dir)

    file_handler = logging.handlers.RotatingFileHandler('{0}/mvedr_logger_alerts.log'.format(log_dir), maxBytes=25000000,
                                                        backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)

    while True:
        try:
            edr = EDR()
            edr.get_alerts()
            edr.session.close()
            logger.info('total API resource count {} '.format(total_api_counts))
            total_api_counts=0
            time.sleep(int(interval))
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                        .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                line_no=exc_tb.tb_lineno, error=str(error)))
