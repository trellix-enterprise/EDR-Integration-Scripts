#!/usr/bin/env python3
# Script to retrieve all threats
# This is a script intended to be a guideline and not supported by Trellix , if you help integrating scripts with EDR reach out to Trellix Professional services

import sys
import requests
import time
import logging
import json
import os
import pytz

from datetime import datetime, timedelta
from dateutil import tz
from logging.handlers import SysLogHandler
from dotenv import load_dotenv

load_dotenv(verbose=True)

total_api_counts = 0
total_threats_count = 0
total_affected_host_count = 0
total_detections_count = 0
date_pattern = '%Y-%m-%dT%H:%M:%SZ'

class EDR():
    
    def __init__(self):
        self.iam_url = 'iam.cloud.trellix.com/iam/v1.0'
        if edr_region == 'EU':
            self.base_url_ui = 'soc.eu-central-1.trellix.com'
        elif edr_region == 'US-W':
            self.base_url_ui = 'soc.trellix.com'
        elif edr_region == 'US-E':
            self.base_url_ui = 'soc.us-east-1.trellix.com'
        elif edr_region == 'SY':
            self.base_url_ui = 'soc.ap-southeast-2.trellix.com'
        elif edr_region == 'GOV':
            self.base_url_ui = 'soc.mcafee-gov.com'
        else:
             logger.error("EDR_REGION is mandatory in .env file, valid values are 'EU', 'US-W', 'US-E', 'SY', 'GOV'")
             sys.exit()
            
        self.base_url='api.manage.trellix.com'

        self.session = requests.Session()

        if valid == 'False':
            self.session.verify = False
        else:
            self.session.verify = True

        if proxy is not None:
            self.session.proxies['https'] = proxy

        creds = (edr_client_id, edr_client_secret)

        self.pattern = '%Y-%m-%dT%H:%M:%S.%f'
        self.cache_fname = '{0}/cache.log'.format(cache_dir)
        if os.path.isfile(self.cache_fname):
            cache = open(self.cache_fname, 'r')
            last_detection = datetime.strptime(cache.read(), date_pattern)
            last_detection_utc = last_detection.replace(tzinfo=pytz.UTC)
            next_pull = last_detection_utc.astimezone(tz.tzlocal()) + timedelta(seconds=1)

            logger.debug('Cache exists. Last detection date UTC: {0}'.format(last_detection))
            logger.debug('Pulling newest threats from: {0}'.format(next_pull))
            cache.close()
        else:
            logger.debug('Cache does not exists. Pulling data from last {0} days.'.format(initial_pull))
            next_pull = datetime.now() - timedelta(days=int(initial_pull))

        self.epoch_pull = str(datetime.timestamp(next_pull)*1000)[:13]
        logger.debug('New pulling date {0} - epoch {1}'.format(next_pull, self.epoch_pull))

        self.auth(creds)
        self.threat_limit = 10000
        self.affectedHostLimit=5000
        self.detections_limit=5000
        global total_api_counts
        total_api_counts=0

    def auth(self, creds):
        try:
            payload = {
                'scope': 'soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr soc.act.tg',
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

    def get_threats(self):
        try:
            global total_api_counts
            global total_threats_count
            global total_affected_host_count
            global total_detections_count
            skip = 0
            tnextflag = True

            filter_params = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter_params['severities'] = severities
            filter_params['scoreRange'] = [30]
            headers = {
                'Content-Type': 'application/vnd.api+json',
                'x-api-key':x_api_key
                }

            while(tnextflag):
                res = self.session.get(
                    'https://{0}/edr/v2/threats?sort=-lastDetected&filter={1}&from={2}&page[limit]={3}&page[offset]={4}'
                        .format(self.base_url, json.dumps(filter_params), self.epoch_pull, self.threat_limit, skip),headers=headers)

                if res.ok:
                    total_api_counts+=1
                    total_threats_count+=1
                    logger.debug("processing threats API response")
                    res = res.json()
                    if  'links' in res and res['links']['next'] == None:
                        tnextflag = False
                    else:
                        skip = skip+self.threat_limit

                    if len(res['data']) > 0:
                        if os.path.isfile(self.cache_fname):
                            cache = open(self.cache_fname, 'r')
                            last_detection = datetime.strptime(cache.read(), date_pattern)
                            cache.close()
                            if last_detection < (datetime.strptime(res['data'][0]['attributes']['lastDetected'], date_pattern)):
                                logger.debug('More recent detection timestamp detected. Updating cache.log.')
                                cache = open(self.cache_fname, 'w')
                                cache.write(res['data'][0]['attributes']['lastDetected'])
                                cache.close()
                            else:
                                logger.debug('More recent detection timestamp in cache.log already saved.')
                        else:
                            cache = open(self.cache_fname, 'w')
                            cache.write(res['data'][0]['attributes']['lastDetected'])
                            cache.close()

                        for threat in res['data']:
                            threat=self.mvision_to_old_format(threat)
                            logger.debug("pulled threat id {0}".format(threat['id']))
                            affected_hosts = self.get_affected_hosts(threat['id'])
                            threat_detections_count = 0
                            detections_host_map = self.get_detections(threat['id'])
                            for affected_host in affected_hosts:
                                maguid = affected_host['attributes']['host']['aGuid']
                                detections = detections_host_map[maguid] # get detections only for the affected hosts
                                if detections is None or not detections:
                                    continue
                                for detection in detections:
                                    detection=self.mvision_to_old_format(detection)
                                    threat['detection'] = detection
                                    traceid = detection['traceId']
                                    logger.debug("pulled detection for trace id {0} , affected Host {1} , threat id {2} and threat last detection date {3}".format(traceid, maguid, threat['id'], threat['lastDetected']))
                                    sha256 = detection['sha256']

                                    threat['url'] = 'https://ui.{0}/monitoring/#/workspace/72,TOTAL_THREATS,{1}?traceId={2}&maGuid={3}&sha256={4}' \
                                        .format(self.base_url_ui, threat['id'], traceid, maguid, sha256)
                                    logger.debug(json.dumps(threat))
                                    logger.info('Retrieved new MVISION EDR Threat Detection. {0}'.format(threat['name']))

                                    if syslog_ip and syslog_port:
                                        syslog.info(json.dumps(threat, sort_keys=True))
                                        logger.info('Successfully send data to Syslog IP {}'.format(syslog_ip))

                                    if threat_log == 'True':
                                        if os.path.exists(threat_dir) is False:
                                            os.mkdir(threat_dir)

                                        time_detect = detection['firstDetected']
                                        ptime_detect = datetime.strptime(time_detect, date_pattern)
                                        filename = '{}-{}.log'.format(ptime_detect.strftime('%Y%m%d%H%M%S'), threat['name'])
                                        file = open('{}/{}'.format(threat_dir, filename), 'w')
                                        file.write(json.dumps(threat))
                                        file.close()
                                    threat_detections_count+=1            
                            logger.debug('For threat {0} identified {1} new detections.'.format(threat['name'], threat_detections_count))
                            
                    else:
                        logger.debug('No new threats identified. Exiting. {0}'.format(res))
                        tnextflag = False # line added to allow loop to finish successfully and cause loop to immediately repeat and bypass the retry interval.
                elif res.status_code==429:
                     retry_interval=self.get_retryinterval(res)
                     logger.debug('Rate Limit Exceed in Threats Api, retrying after  {} sec'.format(retry_interval))
                     time.sleep(int(retry_interval))            
                else:
                    logger.error('Error in retrieving edr.get_threats(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_threats(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_threats(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_threats(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            logger.debug('Pulled total {0} Threats {1} affectedHosts and {2} Detections.'.format(total_threats_count, total_affected_host_count, total_detections_count))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise
    def get_affected_hosts(self, threat_id):
        global total_api_counts
        global total_affected_host_count
        try:
            skip = 0
            anextflag = True
            affhosts = []
            headers = {
                'Content-Type': 'application/vnd.api+json',
                'x-api-key':x_api_key
            }
            while(anextflag):
                res = self.session.get(
                    'https://{0}/edr/v2/threats/{1}/affectedhosts?from={2}&page[limit]={3}&page[offset]={4}'
                        .format(self.base_url, threat_id, self.epoch_pull, self.affectedHostLimit, skip),headers=headers)
                
                if res.ok:
                    total_api_counts+=1
                    total_affected_host_count+=1
                    logger.debug("processing affected host API response")
                    res = res.json()
                    if res['links']['next'] == None:
                        anextflag = False
                    else:
                        skip = skip+self.affectedHostLimit
                    logger.debug('Pulled {0} affectedhosts for {1} threatid'.format(res['meta']['totalResourceCount'], threat_id))
                    if len(affhosts) == 0:
                        affhosts = res['data']
                    else:
                        for affhost in res['data']:
                            affhosts.append(affhost)

                elif res.status_code==429:
                     retry_interval=self.get_retryinterval(res)
                     logger.debug('Rate Limit Exceed in Affected Api, retrying after  {} sec'.format(retry_interval))
                     time.sleep(int(retry_interval))

                else:
                    logger.error('Error in retrieving edr.get_affectedHosts(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_affectedHosts(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_affectedHosts(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_affectedHosts(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            return affhosts

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise
        
    def get_detections(self, threat_id):
        try:
            global total_api_counts
            global total_detections_count
            skip = 0
            dnextflag = True
            detection_host_map = dict()
            headers = {
                'Content-Type': 'application/vnd.api+json',
                'x-api-key':x_api_key
                }

            while(dnextflag):
                res = self.session.get(
                    'https://{0}/edr/v2/threats/{1}/detections?from={2}&page[limit]={3}&page[offset]={4}'
                        .format(self.base_url, threat_id, self.epoch_pull, self.detections_limit, skip),headers=headers)

                if res.ok:
                    total_api_counts+=1
                    total_detections_count+=1
                    logger.debug("processing detections API response")
                    res = res.json()
                    if res['links']['next'] == None:
                        dnextflag = False
                    else:
                        skip = skip+self.detections_limit
                    logger.debug('Pulled {0} detections for {1} threatid'.format(res['meta']['totalResourceCount'], threat_id))
                    for detection in res['data']:
                        host_guid = detection['attributes']['host']['aGuid']
                        if host_guid not in detection_host_map:
                            detection_host_map[host_guid] = []
                        detection_host_map[host_guid].append(detection)
                elif res.status_code==429:
                     retry_interval=self.get_retryinterval(res)
                     logger.debug('Rate Limit Exceed in Detections Api, retrying after  {} sec'.format(retry_interval))
                     time.sleep(int(retry_interval))

                else:
                    logger.error('Error in retrieving edr.get_detections(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_detections(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_detections(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_detections(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            return detection_host_map

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def mvision_to_old_format(self,source):
        data = {}
        json_data=json.loads(json.dumps(source))
        for x in json_data:
            if(x=='type'):
                continue
            if(x=='attributes'):
                nested_json=json.loads(json.dumps(json_data[x]))
                for y in nested_json:
                    data[y]=nested_json[y]
            else:
                data[x]=json_data[x]

        return data
    
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
    edr_region = os.getenv('EDR_REGION')
    edr_client_id = os.getenv('EDR_CLIENT_ID')
    edr_client_secret = os.getenv('EDR_CLIENT_SECRET')

    interval = os.getenv('INTERVAL')
    initial_pull = os.getenv('INITIAL_PULL')

    syslog_ip = os.getenv('SYSLOG_IP')
    syslog_port = os.getenv('SYSLOG_PORT')

    proxy = os.getenv('PROXY')
    valid = os.getenv('VALID')

    cache_dir = os.getenv('CACHE_DIR')

    log_level = os.getenv('LOG_LEVEL')
    log_dir = os.getenv('LOG_DIR')

    threat_log = os.getenv('THREAT_LOG')
    threat_dir = os.getenv('THREAT_DIR')
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

    file_handler = logging.handlers.RotatingFileHandler('{0}/mvedr_logger.log'.format(log_dir), maxBytes=25000000,
                                                        backupCount=5)
    file_handler.setFormatter(formatter)
    logger.addHandler(file_handler)
    if syslog_ip and syslog_port:
        syslog = logging.getLogger('syslog')
        syslog.setLevel(log_level)
        syslog.addHandler(SysLogHandler(address=(syslog_ip, int(syslog_port))))

    while True:
        try:
            edr = EDR()
            edr.get_threats()
            edr.session.close()
            logger.info('total API resource count {} '.format(total_api_counts))
            total_api_counts=0
            total_threats_count=0
            total_affected_host_count=0
            total_detections_count=0
            time.sleep(int(interval))
        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
                                 
            logger.error('total API resource count in exception {} '.format(total_api_counts))
            time.sleep(int(interval))