#!/usr/bin/env python3
# based on a hash, script will automatically launch MVISION EDR query

import sys
import getpass
import time
import requests
import logging
import json

from argparse import ArgumentParser, RawTextHelpFormatter


class EDR():
    def __init__(self):
        self.iam_url = 'iam.cloud.trellix.com/iam/v1.0'
        self.base_url='api.manage.trellix.com'

        self.logging()

        self.session = requests.Session()
        self.session.verify = True

        creds = (args.client_id, args.client_secret)
        self.auth(creds)

        self.pname = args.process

    def logging(self):
        self.logger = logging.getLogger('logs')
        self.logger.setLevel(args.loglevel.upper())
        handler = logging.StreamHandler()
        formatter = logging.Formatter("%(asctime)s;%(levelname)s;%(message)s")
        handler.setFormatter(formatter)
        self.logger.addHandler(handler)

    def auth(self, creds):
        try:

            payload = {
                'scope': 'mi.user.investigate soc.act.tg soc.hts.c soc.hts.r soc.rts.c soc.rts.r soc.qry.pr',
                'grant_type': 'client_credentials'
            }

            headers = {
                'Content-Type': 'application/x-www-form-urlencoded'
            }

            res = self.session.post('https://{0}/token'.format(self.iam_url), headers=headers, data=payload, auth=creds)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug('request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                token = res.json()['access_token']
                self.session.headers = {
                    'Authorization': 'Bearer {}'.format(token),
                    'Content-Type':'application/vnd.api+json',
                    'x-api-key': args.x_api_key
                }
                self.logger.debug('AUTHENTICATION: Successfully authenticated.')
            else:
                self.logger.error('Error in edr.auth(). Error: {0} - {1}'
                                  .format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def search(self):
        try:
            queryId = None

            payload = {
                "data": {
                    "type": "realTimeSearches",
                    "attributes": {
                        "query": "HostInfo hostname, ip_address and Processes name, id, parentimagepath, started_at where Processes name contains "+str(self.pname)
                    }
                }
            }

            res = self.session.post(
                'https://{0}/edr/v2/searches/realtime'.format(self.base_url), json=payload)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug(
                'request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                queryId = res.json()['data']['id']
                self.logger.info(
                    'MVISION EDR search got started successfully {}'.format(queryId))
            else:
                self.logger.error(
                    'Error in edr.search(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

            return queryId

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def search_status(self, queryId):
        try:
            status = False
            res = self.session.get('https://{0}/edr/v2/searches/queue-jobs/{1}'.format(
                self.base_url, str(queryId)), allow_redirects=False)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug(
                'request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.status_code == 303:
                status = True
            else:
                self.logger.info('Search still in process. Status: {}'.format(
                    res.json()['data']['attributes']['status']))
            return status

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def search_result(self, queryId):
        try:
            res = self.session.get(
                'https://{0}/edr/v2/searches/realtime/{1}/results'.format(self.base_url, str(queryId)))

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug(
                'request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                try:
                    items = res.json()['meta']['totalResourceCount']
                    react_summary = []
                    for item in res.json()['data']:
                        react_dict = {}
                        react_dict[item['id']
                                   ] = item['attributes']['Processes.id']
                        react_summary.append(react_dict)

                    self.logger.debug(json.dumps(res.json()))
                    self.logger.info('MVISION EDR search got {} responses for this process name. {}'
                                     .format(items, len(react_summary)))

                    return react_summary

                except Exception as e:
                    self.logger.error(
                        'Something went wrong to retrieve the results. Error: {}'.format(e))
                    exit()
            else:
                self.logger.error(
                    'Error in edr.search_result(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def reaction_execution(self, queryId, systemId, pid):
        try:
            payload = {
                "data": {
                    "type": "searchRemediation",
                    "attributes": {
                        "action": "killProcess",
                        "searchId": queryId,
                        "rowIds": [str(systemId)],
                        "actionInputs": [
                            {
                                "name": "pid",
                                "value": str(pid)
                            }
                        ]
                    }
                }
            }

            res = self.session.post('https://{0}/edr/v2/remediation/search'.format(self.base_url),
                                    json=payload)

            self.logger.debug('request url: {}'.format(res.url))
            self.logger.debug(
                'request headers: {}'.format(res.request.headers))
            self.logger.debug('request body: {}'.format(res.request.body))

            if res.ok:
                rid = res.json()['data']['id']
                self.logger.info(
                    'MVISION EDR reaction got executed successfully')
                return rid
            else:
                self.logger.error(
                    'Error in edr.reaction_execution(). Error {} - {}'.format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))

    def main(self):
        try:

            queryId = self.search()
            if queryId is None:
                exit()

            while self.search_status(queryId) is False:
                time.sleep(30)

            results = self.search_result(queryId)
            if len(results) == 0:
                exit()

            if args.reaction == 'True':
                for result in results:
                    for systemId, filePath in result.items():

                        reaction_id = self.reaction_execution(
                            queryId, systemId, filePath)

                        if reaction_id is None:
                            self.logger.error(
                                'Could not create new MVISION EDR reaction')

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """Usage: python trellix_edr_search_process.py -C <CLIENT_ID> -S <CLIENT_SECRET> -K <X_API_KEY> -PN <process name>"""
    title = 'MVISION EDR Python API'
    parser = ArgumentParser(description=title, usage=usage,
                            formatter_class=RawTextHelpFormatter)

    parser.add_argument('--region', '-R',
                        required=False, type=str,
                        help='[Deprecated] MVISION EDR Tenant Location', choices=['EU', 'US-W', 'US-E', 'SY', 'GOV'])

    parser.add_argument('--client_id', '-C',
                        required=True, type=str,
                        help='MVISION EDR Client ID')

    parser.add_argument('--client_secret', '-S',
                        required=False, type=str,
                        help='MVISION EDR Client Secret')

    parser.add_argument('--x_api_key', '-K',
                        required=True, type=str,
                        help='MVISION API Key')

    parser.add_argument('--process', '-PN', required=True,
                        type=str, default='Process Name to search for')

    parser.add_argument('--reaction', '-RE', required=False,
                        type=str, choices=['True', 'False'],
                        default='False', help='Kill Process')

    parser.add_argument('--loglevel', '-LL', required=False,
                        type=str, choices=['INFO', 'DEBUG'],
                        default='INFO', help='Specify log level')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(
            prompt='MVISION EDR Client Secret: ')

    EDR().main()
