import json
import socket
import gzip
import StringIO
import base64
import sys
import time
import datetime
import threading

import requests
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Hash import SHA512



class FairlayPythonClient(object):

    CATEGORIES = {
        'soccer': 1,
        'tenis': 2,
        'golf': 3,
        'cricket': 4,
        'rugbyunion': 5,
        'boxing': 6,
        'horseracing': 7,
        'motorsport': 8,
        'special': 10,
        'rugbyleague': 11,
        'backetball': 12,
        'americanfootball': 13,
        'baseball': 14,
        'politics': 15,
        'financial': 16,
        'greyhound': 17,
        'volleyball': 18,
        'handball': 19,
        'darts': 20,
        'bandy': 21,
        'wintersports': 22,
        'bowls': 24,
        'pool': 25,
        'snooker': 26,
        'tabletennis': 27,
        'chess': 28,
        'hockey': 30,
        'fun': 31,
        'esports': 32,
        'inplay': 33,
        'reserved4': 34,
        'mixedmartialarts': 35,
        'reserved6': 36,
        'reserved': 37,
        'cycling': 38,
        'reserved9': 39,
        'bitcoin': 40,
        'badminton': 42
    }

    ENDPOINTS = {
        'get_orderbook': 1,
        'get_server_time': 2,
        'get_market': 6,
        'create_market': 11,
        'cancel_all_orders': 16,
        'get_balance': 22,
        'get_unmatched_orders': 25,
        'get_matched_orders': 27,
        'set_absence_cancel_policy': 43,
        'set_force_nonce': 44,
        'set_read_only': 49,
        'change_orders': 61,
        'cancel_orders_on_markets': 83
    }

    CONFIG = {
        'SERVERIP': '31.172.83.53',
        'PORT': 18017,
        'APIAccountID': 1,
        'ID': 'CHANGETHIS',
        'SERVERPUBLICKEY': ('-----BEGIN PUBLIC KEY-----\n'
                            'MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC52cTT4XaVIUsmzfDJBP/ZbneO\n'
                            '6qHWFb01oTBYx95+RXwUdQlOAlAg0Gu+Nr8iLqLVbam0GE2OKfrcrSy0mYUCt2Lv\n'
                            'hNMvQqhOUGlnfHSvhJBkZf5mivI7k0VrhQHs1ti8onFkeeOcUmI22d/Tys6aB20N\n'
                            'u6QedpWbubTrtX53KQIDAQAB\n'
                            '-----END PUBLIC KEY-----')
    }

    def __init__(self):
        super(FairlayPythonClient, self).__init__()
        self.__load_config()

    def __load_config(self):
        try:
            with open('config.txt') as config:
                try:
                    temp = json.load(config)
                    self.CONFIG.update(temp)
                    required_keys = ['PrivateRSAKey', 'PublicRSAKey', 'ID']
                    if ([x for x in required_keys if x not in self.CONFIG.keys() or not self.CONFIG[x]] or
                        self.CONFIG['ID'] == 'CHANGETHIS'):
                        raise EnvironmentError('Missing user ID or Public/Private keys in config file')
                except ValueError:
                    raise EnvironmentError('Something is wrong with the config file')
        except IOError:
            self.__generate_keys()

            with open('config.txt', 'w') as config:
                json.dump(self.CONFIG, config, indent=4)

            print '==================================================================='
            print 'It appears that you don\'t have a config file, so we created'
            print 'a new one with a brand new key pair.'
            print ''
            print 'Please visit:  http://fairlay.com/user/dev and register a new API'
            print 'Account with the following public key:'
            print ''
            print self.CONFIG['PublicRSAKey']
            print ''
            print '** Don\'t forget to to change ID and APIAccountID fields in'
            print '   the config.txt file.'
            print '==================================================================='
            print ''
            sys.exit(0)

    def __generate_keys(self, bits=2048):
        new_key = RSA.generate(bits, e=65537)
        public_key = new_key.publickey().exportKey('PEM')
        private_key = new_key.exportKey('PEM')
        self.CONFIG['PublicRSAKey'] = public_key
        self.CONFIG['PrivateRSAKey'] = private_key

    def __send_request(self, endpoint, data=None):
        nonce = int(round(time.time() * 1000))
        endpoint_code = self.ENDPOINTS[endpoint] + 1000 * self.CONFIG['APIAccountID']

        message = "{}|{}|{}".format(nonce, self.CONFIG['ID'], endpoint_code)
        if data:
            message += '|' + data
        sign = self.__sign_message(message)
        message = '{}|{}<ENDOFDATA>'.format(sign, message)

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(15)
            s.connect((self.CONFIG['SERVERIP'], self.CONFIG['PORT']))
            s.send(message)

            data = ''
            while True:
                new_data = s.recv(4096)
                if not new_data:
                    break
                data += new_data
            s.close()
            response = gzip.GzipFile(fileobj=StringIO.StringIO(data)).read()
        except socket.timeout, socket.error:
            return

        if not self.__verify_response(response):
            raise ValueError

        response = response.split('|')[-1]

        if response == 'XError: Service unavailable':
            time.sleep(6)
            return self.__send_request(endpoint, data)

        if response.startswith('XError'):
            raise IOError(response.replace('XError:', ''))
        return response

    def __verify_response(self, message):
        idx = message.find('|')
        if idx == -1:
            return True

        signed_message = message[:idx]
        original_message = message[idx+1:]
        key = RSA.importKey(self.CONFIG['SERVERPUBLICKEY'])
        signer = PKCS1_v1_5.new(key)
        digest = SHA512.new()
        digest.update(original_message)
        if signer.verify(digest, base64.b64decode(signed_message + "=" * ((4 - len(signed_message) % 4) % 4))):
            return True

    def __sign_message(self, message):
        key = RSA.importKey(self.CONFIG['PrivateRSAKey'])
        signer = PKCS1_v1_5.new(key)
        digest = SHA512.new()
        digest.update(message)
        sign = signer.sign(digest)
        return base64.b64encode(sign)

    def __public_request(self, endpoint, json=True):
        while True:
            try:
                response = requests.get('http://31.172.83.181:8080/free/' + endpoint)

                if response == 'XError: Service unavailable':
                    raise requests.exceptions.ConnectionError

                if 'XError' in response.text:
                    return

                if json:
                    return response.json()
                else:
                    return response
            except requests.exceptions.ConnectionError:
                pass
            sleep(6)

    def get_markets_and_odds(self, market_filter={}, changed_after=datetime.datetime(2015, 1, 1)):
        '''
            Free Public API for retrieving markets and odds. Check the documentation at:
            http://piratepad.net/APVEoUmQPS

            market_filter: dictionary
            change_after: datetime
        '''
        filters = {'ToID': 10000, 'SoftChangedAfter': changed_after.isoformat()}
        filters.update(market_filter)

        try:
            response = self.__public_request('markets/{}'.format(json.dumps(filters)))
        except ValueError:
            return

        for market in response:
            market['OrdBStr'] = [json.loads(ob) for ob in market['OrdBStr'].split('~') if ob]
        return response

    def get_server_time(self):
        return self.__send_request('get_server_time')

    def get_balance(self):
        response = self.__send_request('get_balance')
        if response:
            try:
                return json.loads(response)
            except ValueError:
                return None

    def get_orders(self, order_type, timestamp=1420070400L, market_id=None):
        '''
            order_type: 'matched' or 'unmatched'
        '''
        max_items = 1500
        start = 0
        orders = []

        while True:
            if market_id:
                message = str(timestamp) + '|' + str(market_id)
            else:
                message = str(timestamp) + '|' + str(start) + '|' + str(start + max_items)

            response = self.__send_request('get_'+ order_type +'_orders', message)

            try:
                temp = json.loads(response)
                if market_id:
                    return temp
                orders += temp
            except ValueError:
                break

            if len(temp) < max_items:
                break
            else:
                start += max_items
        return orders

    def change_orders(self, orders_list=[]):
        '''
            Allows you to create, cancel and alter orders
            Set Pri to 0  to cancel an order
            Set Oid to -1 to create an order
            ** Maximum allowed orders in one request: 50

            orders_list:
                Mid: Market ID
                Rid: Runner ID  I.E.: 0 -> 1st runner, 1 -> 2nd runner, ...
                Oid: Order ID  (should be set to -1 if no old order shall be replaced)
                Am: Amount in mBTC. In case of ask orders this amount represents the liability, in case of bid orders this amount represents the possible winnings.
                Pri: Price with 3 decimals
                Sub:  Custom String
                Type: 0 -> MAKERTAKER, 1 -> MAKER, 2 -> TAKER
                Boa: Must be 0 for Bid Orders  and 1 for Ask.  Ask means that you bet on the outcome to happen.
                Mct: Should be set to 0
        '''
        if len(orders_list) > 50:
            return

        message = []
        for order in orders_list:
            temp = {}
            for k, v in order.items():
                temp[k] = str(v) if k in ['Mid', 'Rid', 'Oid'] else v
            message.append(temp)
        response = self.__send_request('change_orders', json.dumps(message))

        try:
            response = json.loads(response)
        except ValueError:
            return None

        markets_to_cancel = []
        response_orders = []
        for idx, order in enumerate(orders_list):
            response_order = response[idx]
            if 'YError:Market Closed' in response_order or response_order == 'Order cancelled':
                pass
            elif 'YError' in response_order:
                markets_to_cancel.append(orders_list[idx]['Mid'])

        self.cancel_orders_on_markets(markets_to_cancel)
        return [json.loads(x) for x in response]

    def get_market(self, market_id):
        message = str(market_id)
        response = self.__send_request('get_market', message)

        try:
            market = json.loads(response)
            market['OrdBStr'] = [json.loads(ob) for ob in market['OrdBStr'].split('~') if ob]
            return market
        except ValueError:
            return None

    def get_odds(self, market_id):
        message = str(market_id)
        response = self.__send_request('get_orderbook', message)

        if not ('Bids' in response or 'Asks' in response):
            return []
        try:
            return [json.loads(ob) for ob in response.split('~') if ob]
        except ValueError:
            return []

    def create_market(self, data):
        ''' data dictionary:
                competition: string
                description: string
                title: string,
                category: must be an ID from CATEGORIES
                closing_date: string in format YYYY-MM-DDTHH:MM:SS
                resolution_date: string in format YYYY-MM-DDTHH:MM:SS
                username: string
                outcomes: list of strings ie: ['Outcome X', 'Outcome Y']
        '''

        if data['category'] not in self.CATEGORIES.values():
            return

        dic = {
            'Comp': data['competition'],
            'Descr': data['description'],
            'Title': data['title'],
            'CatID': data['category'],
            'ClosD': data['closing_date'],
            'SettlD': data['resolution_date'],
            'PrivCreator': self.CONFIG['ID'],
            'CreatorName': data['username'],
            'Status': 0,
            '_Type': 2,
            '_Period': 1,
            'SettlT': 0,
            'Comm': 0.02,
            'Pop': 0.0,
            'Ru': []
        }

        for run in data['outcomes']:
            dic['Ru'].append({'Name': run, 'InvDelay': 0, 'VisDelay': 0})

        message = json.dumps(dic)
        return self.__send_request('create_market', message)

    def cancel_orders_on_markets(self, market_ids=[]):
        response = self.__send_request('cancel_orders_on_markets', str([str(x) for x in market_ids]))
        return int(response.split(' ')[0])

    def cancel_all_orders(self):
        response = self.__send_request('cancel_all_orders')
        if response:
            return int(response.split(' ')[0])

    def set_absence_cancel_policy(self, miliseconds):
        response = self.__send_request('set_absence_cancel_policy', str(miliseconds))
        return True if response =='success' else False

    def set_force_nonce(self, force):
        force = 'true' if force else 'false'
        response = self.__send_request('set_force_nonce', force)
        return True if response =='success' else False

    def set_ready_only(self):
        response = self.__send_request('set_ready_only')
        if 'success' in response:
            return True

# client = FairlayPythonClient()
# print client.get_markets_and_odds({'ToID': 10})



###############################################################################
###############################################################################

class FairlayMarketFetcher(object):
    markets = []
    last_fetch_date = datetime.datetime(2016, 01, 01)

    def __init__(self):
        super(FairlayMarketFetcher, self).__init__()
        self.client = FairlayPythonClient()
        self.event = threading.Event()
        threading.Thread(target=self.__run).start()

    def __run(self):
        while not self.event.is_set():
            self.fetch_new_markets()
            self.last_fetch_date = datetime.datetime.now()
            self.event.wait(60 * 5)  # 5 minutes

    def fetch_new_markets(self):
        from_id = 0
        increment = 100

        new_markets = []
        while True:
            filters = {'FromID': from_id, 'ToID': from_id + increment}
            new_markets += self.client.get_markets_and_odds(filters, self.last_fetch_date)

            if len(new_markets) < increment:
                break
            else:
                from_id += increment
            time.sleep(2)

        now = datetime.datetime.now() - datetime.timedelta(minutes=30)
        for idx, market in enumerate(self.markets):
            closing_date = datetime.datetime.strptime(market['ClosD'][:19], '%Y-%m-%dT%H:%M:%S')
            if closing_date < now:
                del self.market[idx]

        self.markets += new_markets

    def stop(self):
        self.event.set()

# fetcher = FairlayMarketFetcher()
# while True:
#     try:
#         time.sleep(1)
#     except KeyboardInterrupt:
#         fetcher.stop()
#         break



###############################################################################
###############################################################################

class FairlayOrderMatching(object):
    matched_orders = []

    def __init__(self):
        super(FairlayOrderMatching, self).__init__()
        self.client = FairlayPythonClient()
        self.create_order()

    def create_order(self):
        order = {
            'Mid': 58097313763,
            'Rid': 0,
            'Oid': -1,
            'Am': 10,
            'Pri': 1.564,
            'Sub': '',
            'Type': 0,
            'Boa': 1,
            'Mct': 0
        }
        order = self.client.change_orders([order])[0]
        self.get_matched(order['PrivID'])

    def get_matched(self, order_id):
        time.sleep(6)
        temp = self.client.get_orders('matched')

        for match in temp:
            if match['_UserUMOrderID'] == order_id:
                self.matched_orders.append(match)

# matching = FairlayOrderMatching()
