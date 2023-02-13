#!/usr/bin/env python3
# Written by mohlcyber v.1.7 (13.06.2022)
# Script to retrieve all threats from the monitoring dashboard

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


class EDR():
    def __init__(self):
        self.iam_url = 'preprod.iam.mcafee-cloud.com/iam/v1.1'
        if edr_region == 'Local':
            self.base_url = 'us-west-2-api-inteks-ls.mvisionapiedr.net'
        elif edr_region == 'US-W':
            self.base_url = 'soc.trellix.com'
        elif edr_region == 'US-E':
            self.base_url = 'soc.us-east-1.trellix.com'
        elif edr_region == 'SY':
            self.base_url = 'soc.ap-southeast-2.trellix.com'
        elif edr_region == 'GOV':
            self.base_url = 'soc.mcafee-gov.com'

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
            logger.debug('last detections is '.format(cache))
            last_detection = datetime.strptime(cache.read(), '%Y-%m-%dT%H:%M:%SZ')
            
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
        self.limit = 10000

    def auth(self, creds):
        try:
            payload = {
                'scope': 'soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
                'grant_type': 'client_credentials',
                'audience': 'mcafee'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)

            if res.ok:
                token = res.json()['access_token']
                #token='eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6IndCTlpJN1JnWFlncmFkdHJYU3Z3dXZtVlVkRSIsImtpZCI6IndCTlpJN1JnWFlncmFkdHJYU3Z3dXZtVlVkRSJ9.eyJpc3MiOiJodHRwczovL3ByZXByb2QuaWFtLm1jYWZlZS1jbG91ZC5jb20vaWFtL3YxLjAiLCJuYmYiOjE2NzYwMDMxNzUsInN1YiI6IjAwdTFlZTk0bWJ6YnRNQkljMGg4Iiwic2NvcGUiOiJlcG8uYWRtaW4gbWkudXNlci5jb25maWcgc29jLmFjdC50ZyBzb2MuaHRzLmMgc29jLmh0cy5yIHNvYy5ydHMuYyBzb2MucnRzLnIgb3BlbmlkIiwidGVuYW50X2lkIjoiN0U4N0I0NEYtODBEQi00NzM1LUFGMDQtRkVCNUFDNkYxOTY2IiwiYXVkIjoibWNhZmVlIiwiZ2l2ZW5fbmFtZSI6IkZOMjgxMDQwMiIsImNsaWVudF9pZCI6IjBvYWU2dmZqNmdDRUlzTUlkMGg3IiwibG9jYWxlIjoiZW5fVVMiLCJleHAiOjE2NzYwODk1ODUsImlkcCI6IjAwb2VwMnl2b3FiS1NNOWtOMGg3IiwiZW1haWwiOiJ0ZXN0MjgxMDQwMkB5b3BtYWlsLkNPTSIsImZhbWlseV9uYW1lIjoiTE4yODEwNDAyIiwidG9rZW5faWQiOiJOQ01nYW9mQTliSFVDWDZVLV8xbVM1MGZDIiwiem9uZWluZm8iOiIiLCJsb2dpbl9oaW50IjoidGVzdDI4MTA0MDJAeW9wbWFpbC5DT00iLCJub25jZSI6IiJ9.fK7aI1zqaYfy5MxzCvdm8GpO5j3fjG-EK2-qukDWsP0U0FDB228UlWx8huwtXKwLs2_bN4egBKEw9lLN1ELDOKhmpRLKvYTO7zj8QwAy2F6LjXZr03J4-bhYJY8gwIumvXbtxdHFK6enU3nWYU-XW0OEp0-gROMBAAnlurVTGeySurTKXQ3C629jYD4VCJBIHJudhI0rLCJaW61gs1ooIytCzm5Gd6I65izzaBhnUHJCSyKAg-4-SIx0PhCZs9SvhlWfT9jR7UheKD0MiGEELzAfIvCujROoS31_PQMfV4LrN9vJzjGI_ZhfB1u3HMH2Uba_dg2dKVyB9aA5fbvMZw'
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
            tthreat = 0
            tdetect = 0
            skip = 0
            tnextflag = True

            filter = {}
            severities = ["s0", "s1", "s2", "s3", "s4", "s5"]
            filter['severities'] = severities
            filter['scoreRange'] = [30]
            headers = {
                'Content-Type': 'application/vnd.api+json',
                'x-api-key':x_api_key
                }

            while(tnextflag):
                res = self.session.get(
                    'https://{0}/edr/v2/threats?sort=-lastDetected&filter={1}&from={2}&page[limit]={3}&page[offset]={4}'
                        .format(self.base_url, json.dumps(filter), self.epoch_pull, self.limit, skip),headers=headers)

                if res.ok:
                    res = res.json()
                    if res['links']['next'] == None:
                        tnextflag = False
                    else:
                        skip = skip+self.limit

                    if len(res['data']) > 0:
                        if os.path.isfile(self.cache_fname):
                            cache = open(self.cache_fname, 'r')
                            last_detection = datetime.strptime(cache.read(), '%Y-%m-%dT%H:%M:%SZ')
                            logger.debug('threat last detection datae {}'.format(last_detection))
                            cache.close()
                            if last_detection < (datetime.strptime(res['data'][0]['attributes']['lastDetected'], '%Y-%m-%dT%H:%M:%SZ')):
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
                            threat_resp=self.json_convertor(threat)
                            affhosts = self.get_affected_hosts(threat['id'])
                            ddetect_count = 0
                            for host in affhosts:
                                detections = self.get_detections(threat['id'], host['id'])

                                for detection in detections:
                                    threat['detection'] = detection
                                    detection_resp=self.json_convertor(detection)
                                    threat_resp['detection']=detection_resp
                                    logger.debug('our detection is {}'.format(detection))
                                    traceid = detection['attributes']['traceId']
                                    maguid = detection['attributes']['host']['maGuid']
                                    sha256 = detection['attributes']['sha256']

                                    threat['url'] = 'https://ui.{0}/monitoring/#/workspace/72,TOTAL_THREATS,{1}?traceId={2}&maGuid={3}&sha256={4}' \
                                        .format(self.base_url, threat['id'], traceid, maguid, sha256)
                                    threat_resp['url']=threat['url']
                                    logger.debug(json.dumps(threat))
                                    logger.info('Retrieved new MVISION EDR Threat Detection. {0}'.format(threat['attributes']['name']))

                                    if syslog_ip and syslog_port:
                                        syslog.info(json.dumps(threat_resp, sort_keys=True))
                                        logger.info('Successfully send data to Syslog IP {}'.format(syslog_ip))

                                    if threat_log == 'True':
                                        if os.path.exists(threat_dir) is False:
                                            os.mkdir(threat_dir)

                                        time_detect = detection['attributes']['firstDetected']
                                        ptime_detect = datetime.strptime(time_detect, '%Y-%m-%dT%H:%M:%SZ')
                                        filename = '{}-{}-{}-{}.log'.format(ptime_detect.strftime('%Y%m%d%H%M%S'), threat['attributes']['name'],threat['id'],host['id'])
                                        file = open('{}/{}'.format(threat_dir, filename), 'w')
                                        file.write(json.dumps(threat_resp))
                                        file.close()

                                    tdetect += 1
                                    ddetect_count += 1

                            logger.debug('For threat {0} identified {1} new detections.'.format(threat['attributes']['name'], ddetect_count))
                            tthreat += 1

                    else:
                        logger.debug('No new threats identified. Exiting. {0}'.format(res))

                else:
                    logger.error('Error in retrieving edr.get_threats(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_threats(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_threats(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_threats(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            logger.debug('Pulled total {0} Threats and {1} Detections.'.format(tthreat, tdetect))

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def get_affected_hosts(self, threatId):
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
                    'https://{0}/edr/v2/threats/{1}/affectedhosts?sort=-rank&from={2}&page[limit]={3}&page[offset]={4}'
                        .format(self.base_url, threatId, self.epoch_pull, self.limit, skip),headers=headers)
                
                if res.ok:
                    res = res.json()
                    if res['links']['next'] == None:
                        anextflag = False
                    else:
                        skip = skip+self.limit

                    if len(affhosts) == 0:
                        affhosts = res['data']
                    else:
                        for affhost in res['data']:
                            affhosts.append(affhost)

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

    def get_detections(self, threatId, affhost):
        try:
            skip = 0
            dnextflag = True
            detections = []
            headers = {
                'Content-Type': 'application/vnd.api+json',
                'x-api-key':x_api_key
                }

            while(dnextflag):
                filter = {
                    'affectedHostId': affhost
                }

                res = self.session.get(
                    'https://{0}/edr/v2/threats/{1}/detections?sort=-rank&from={2}&filter={3}&page[limit]={4}&page[offset]={5}'
                        .format(self.base_url, threatId, self.epoch_pull, json.dumps(filter), self.limit, skip),headers=headers)

                if res.ok:
                    res = res.json()
                    if res['links']['next'] == None:
                        dnextflag = False
                    else:
                        skip = skip+self.limit

                    if len(detections) == 0:
                        detections = res['data']
                    else:
                        for detection in res['data']:
                            detections.append(detection)
                else:
                    logger.error('Error in retrieving edr.get_detections(). Request url: {}'.format(res.url))
                    logger.error('Error in retrieving edr.get_detections(). Request headers: {}'.format(res.request.headers))
                    logger.error('Error in retrieving edr.get_detections(). Request body: {}'.format(res.request.body))
                    raise Exception('Error in retrieving edr.get_detections(). Error: {0} - {1}'.format(str(res.status_code), res.text))

            return detections

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                         .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                 line_no=exc_tb.tb_lineno, error=str(error)))
            raise

    def mvision_to_martin_formatter(self,source):
        data = {}
        thisdict=json.loads(json.dumps(source))
        for x in thisdict:
            if(x=='type'):
                continue
            if(x=='attributes'):
                nesteddict=json.loads(json.dumps(thisdict[x]))
                for y in nesteddict:
                    data[y]=nesteddict[y]
            else:
                data[x]=thisdict[x]

        return data

def load_env():
    os.environ['EDR_REGION'] = 'Local'
    os.environ['EDR_CLIENT_ID'] = 'EwfiwMeGFh41Xm_4a1UfULhQL'
    os.environ['EDR_CLIENT_SECRET'] = 'Ilo4INGOvI0Rn5esIz03xKXWf'
    os.environ['INTERVAL'] = '300'
    os.environ['INITIAL_PULL'] = '30'
    os.environ['SYSLOG_IP'] = '10.54.1.19'
    os.environ['SYSLOG_PORT'] = '514'
    os.environ['CACHE_DIR'] = '/home/mcafee/work/python_task_snj/martin_ohl_cache'
    os.environ['LOG_LEVEL'] = 'DEBUG'
    os.environ['LOG_DIR'] = '/home/mcafee/work/python_task_snj/martin_logs'
    os.environ['THREAT_LOG'] = 'True'
    os.environ['THREAT_DIR'] = '/home/mcafee/work/python_task_snj/martin_threats'
    os.environ['X_API_KEY']='UTM0bXRyM1RockZMR1BlMm9CSFZiTXBBanNQWnlCVjlHSVExUFJmNW1jZzp1cy13ZXN0LTI'
if __name__ == '__main__':
    load_env()
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
    logger.debug('@@@@@@@@@@@@@@@@@@@ {}'.format(edr_client_id))
    if syslog_ip and syslog_port:
        syslog = logging.getLogger('syslog')
        syslog.setLevel(log_level)
        syslog.addHandler(SysLogHandler(address=(syslog_ip, int(syslog_port))))

    while True:
        try:
            edr = EDR()
            edr.get_threats()
            edr.session.close()
            time.sleep(int(interval))
        except Exception:
            time.sleep(60)