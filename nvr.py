import sys
import json
import base64
import random
import pprint
import hashlib
import argparse

import requests
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5


class cached_property:
    def __init__(self, func):
        self.func = func

    def __get__(self, instance, cls=None):
        result = instance.__dict__[self.func.__name__] = self.func(instance)
        return result


class DahuaDevice:
    def __init__(self, host):
        self.host = host
        self.uri = f'http://{self.host}/RPC2'
        self.login_uri = f'http://{self.host}/RPC2_Login'
        self.last_request_id = 0
        self.session_id = None
        self.key = None

    def request(self, method, params, uri=None, raise_for_result=True):
        if uri is None:
            uri = self.uri

        self.last_request_id += 1

        body = {
            'method': method,
            'params': params,
            'id': self.last_request_id,
        }

        headers={}

        if self.session_id:
            body['session'] = self.session_id

        resp = requests.post(uri, data=json.dumps(body), headers=headers)
        resp.raise_for_status()
        resp_body = resp.json()
        self.session_id = resp_body.get('session')

        if raise_for_result and not resp_body['result']:
            raise Exception('Request failed', resp_body)

        return resp_body

    def login(self, username, password):
        dahua_json = self.request('global.login', {
            "userName": "admin",
            "password": "",
            "clientType": "Dahua3.0-Web3.0"
        }, uri=self.login_uri, raise_for_result=False)

        encryption = dahua_json['params']['encryption']

        if encryption == 'Default':
            self.key = dahua_md5_hash(dahua_json['params']['random'], dahua_json['params']['realm'], username, password)
        elif encryption == 'OldDigest':
            self.key = sofia_hash(password)
        else:
            raise Exception('Unknown encryption', encryption)

        resp = self.request('global.login', {
            "userName": username,
            "password": self.key,
            "clientType": "Dahua3.0-Web3.0", 
            "authorityType": "Default",
            "passwordType": "Default"
        }, uri=self.login_uri)

        if not resp['result']:
            raise Exception('Login failed', resp)

        return resp

    def logout(self):
        if not self.session_id:
            return

        self.request('global.logout', '')
        self.last_request_id = 0
        self.session_id = None
        del self.rsa_pub_key

    @cached_property
    def rsa_pub_key(self):
        encrypt_info = self.request('Security.getEncryptInfo', '')
        pub_key = {p[0]: p[1] for p in (p.split(':') for p in encrypt_info['params']['pub'].split(','))}
        return RSA.construct((int(pub_key['N'], 16), int(pub_key['E'], 16)))

    def secure_request(self, method, params, raise_for_result=True):
        def gen_password(ln):
            if ln > 16:
                ln = 16
            rnd = str(random.random())
            if rnd[len(rnd)-ln: 1] == '0':
                return a(ln)
            else:
                return rnd[len(rnd)-ln:]

        def pad(data):
            block_size = 16
            bytes_to_add = block_size - ((len(data) % block_size) or block_size)
            return data + (b'\0' * bytes_to_add)

        def unpad(data):
            while data[-1] == 0:
                data = data[:-1]
            return data

        password = gen_password(16).encode('utf-8')

        cipher = PKCS1_v1_5.new(self.rsa_pub_key)
        salt = cipher.encrypt(password).hex()

        cipher = AES.new(password, AES.MODE_ECB)
        body = pad(json.dumps(params).encode('utf-8'))

        content = base64.b64encode(cipher.encrypt(body)).decode('ascii')

        ret = self.request(method, {
            'salt': salt,
            'cipher': 'AES-128',
            'content': content,
        })

        content = base64.b64decode(ret['params']['content'])
        body = unpad(cipher.decrypt(content))

        params = json.loads(body)
        ret['params'] = params

        return ret


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--address', required=True, help='NVR address')
    parser.add_argument('--username', required=True, help='NVR username')
    parser.add_argument('--password', required=True, help='NVR password')
    subparsers = parser.add_subparsers(required=True, dest='command')

    commands = {}
    for cmd_class in Command.registry.values():
        cmd = cmd_class()
        subparser = subparsers.add_parser(cmd.name, help=cmd.help_text)
        cmd.configure_parser(subparser)
        commands[cmd.name] = cmd

    args = parser.parse_args()
    cmd = commands[args.command]

    device = DahuaDevice(args.address)
    resp = device.login(args.username, args.password)

    try:
        cmd.run(device, args)
    finally:
        try:
            device.logout()
        except Exception as e:
            pass


def dahua_md5_hash(dahua_random, dahua_realm, username, password):
    str1 = username + ':' + dahua_realm + ':' + password
    hash1 = hashlib.md5(str1.encode()).hexdigest().upper()
    str2 = username + ':' + dahua_random + ':' + hash1
    hash2 = hashlib.md5(str2.encode()).hexdigest().upper()
    return hash2


# From: https://github.com/tothi/pwn-hisilicon-dvr
# Xiongmaitech and Dahua share same 48bit password hash
def sofia_hash(msg):
    h = ""
    m = hashlib.md5()
    m.update(msg)
    msg_md5 = m.digest()
    for i in range(8):
        n = (ord(msg_md5[2*i]) + ord(msg_md5[2*i+1])) % 0x3e
        if n > 9:
            if n > 35:
                n += 61
            else:
                n += 55
        else:
            n += 0x30
        h += chr(n)
    return h


class RegistryMeta(type):
    def __init__(cls, name, bases, attrs):
        super().__init__(name, bases, attrs)
        if bases:
            bases[-1].registry[cls.name] = cls


class Command(metaclass=RegistryMeta):
    name = None
    help_text = None
    registry = {}

    def configure_parser(self, parser):
        return

    def run(self, device, args):
        raise NotImplementedError


class InfoCommand(Command):
    name = 'info'
    help_text = 'print info about NVR and cameras'

    def run(self, device, args):
        print('NVR serial no.:', device.request('magicBox.getSerialNo', '')['params']['sn'])

        print('CAMERAS:')
        pprint.pprint(device.secure_request('LogicDeviceManager.secGetCameraAll', None)['params']['camera'])

        print('STATE:')
        pprint.pprint(device.request('LogicDeviceManager.getCameraState', {'uniqueChannels': [-1]})['params']['states'])


class ToggleCommand(Command):
    name = 'toggle'
    help_text = 'toggle CAM by number ON/OFF'

    def configure_parser(self, parser):
        parser.add_argument('cam_no', type=int, help='camera no.')

    def run(self, device, args):
        cam_no = args.cam_no

        cameras = device.secure_request('LogicDeviceManager.secGetCameraAll', None)['params']['camera']
        cameras = {c['UniqueChannel']: c for c in cameras}

        try:
            cam = cameras[cam_no - 1]
        except KeyError:
            sys.exit(f'CAM {cam_no} is not registered')

        if not cam.get('Enable'):
            sys.exit(f'CAM {cam_no} is not enabled')

        username = cam['DeviceInfo']['UserName']
        off_suffix = '_OFF_'
        turned_off = username.endswith(off_suffix)
        if turned_off:
            username = username[:-len(off_suffix)]
        else:
            username += off_suffix

        # unknown field added on `LogicDeviceManager.secSetCamera`
        cam['DeviceInfo']['VideoInputChannels'] = None
        cam['DeviceInfo']['UserName'] = username
        device.secure_request('LogicDeviceManager.secSetCamera', {'cameras': [cam]})

        turned_off = not turned_off
        if turned_off:
            print(f'CAM {cam_no} turned off')
        else:
            print(f'CAM {cam_no} turned on')


if __name__ == '__main__':
    main()
