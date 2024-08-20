#!/usr/bin/env python3
# Script to query action history

import sys
import getpass
import requests
import json
import logging

from argparse import ArgumentParser, RawTextHelpFormatter

import trellix_edr_action_history_legacy


class EDR():
    def __init__(self):

        self.iam_url = 'iam.cloud.trellix.com/iam/v1.0'
        self.base_url='api.manage.trellix.com'
        self.logging()
        
        self.session = requests.Session()
        self.session.verify = True

        if args.proxy == 'True':
            proxies = {
                'https': 'http://1.1.1.1:9090'
            }
            self.session.proxies = proxies

        creds = (args.client_id, args.client_secret)

        self.auth(creds)

        self.limit = args.limit

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

    def action_history(self):
        try:
            res = self.session.get('https://{0}/edr/v2/remediation/actions?page[limit]={1}'
                                   .format(self.base_url, str(self.limit)))

            self.logger.debug('request url: {}'.format(res.url))

            if res.ok:
                self.logger.info(
                    'SUCCESS: Successful retrieved action history')
                if (args.is_legacy == 'True'):
                    trellix_edr_action_history_legacy.action_history_legacy(
                        self.logger, res.json(), self.limit)
                else:
                    self.logger.info(json.dumps(res.json()))
            else:
                self.logger.error(
                    'edr.action_history. Error: {0} - {1}'.format(str(res.status_code), res.text))
                exit()

        except Exception as error:
            exc_type, exc_obj, exc_tb = sys.exc_info()
            self.logger.error("ERROR: Error in {location}.{funct_name}() - line {line_no} : {error}"
                              .format(location=__name__, funct_name=sys._getframe().f_code.co_name,
                                      line_no=exc_tb.tb_lineno, error=str(error)))


if __name__ == '__main__':
    usage = """python trellix_edr_action_history.py -C <CLIENT_ID> -S <CLIENT_SECRET> -K <X_API_KEY> -legacy <IS_LEGACY> -P <PROXY> -L <LIMIT> -LL <LOG_LEVEL>"""
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

    parser.add_argument('--is_legacy', '-legacy',
                        required=False, type=str, choices=['True', 'False'], default='False',
                        help='Is Old Format Required')

    parser.add_argument('--proxy', '-P',
                        required=False, type=str, choices=['True', 'False'], default='False',
                        help='Provide Proxy JSON in line 35')

    parser.add_argument('--limit', '-L',
                        required=False, type=int, default=1000,
                        help='Set the maximum number of events returned')

    parser.add_argument('--loglevel', '-LL',
                        required=False, type=str, choices=['INFO', 'DEBUG'], default='INFO',
                        help='Set Log Level')

    args = parser.parse_args()
    if not args.client_secret:
        args.client_secret = getpass.getpass(
            prompt='MVISION EDR Client Secret: ')

    edr = EDR()
    edr.action_history()
