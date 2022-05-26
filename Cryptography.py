import datetime
import random
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
import json

class Timestamper:
    def __init__(self, delay, nonceWidth):
        '''Creates a new Timestamper
        delay -> datetime
        nonceWidth -> int'''
        self._delay=delay
        self._nonceWidth=nonceWidth
        self._nonces=[]

    def stamp(self, dct):
        dct["Timestamp"]=datetime.datetime.now().timestamp()
        nonce=random.getrandbits(self._nonceWidth)
        while(nonce in self._nonces):
            nonce=random.getrandbits(self._nonceWidth)
        dct["Nonce"]=nonce
        self._nonces.append(nonce)

    def checkStamp(self, dct):
        if dct["Nonce"] in self._nonces:
            return False
        self._nonces.append(dct["Nonce"])
        timestamp=datetime.datetime.fromtimestamp(dct["Timestamp"])
        current_time=datetime.datetime.now()
        if (current_time-timestamp>delay):
            return False
        return True
        
class SecureConnection:
    def __init__(self):
        '''Generate key pair for own use.'''
        key = RSA.generate(2048)
        self.own_private_key = key
        self.own_public_key = key.public_key()

        self._remote_public_key=RSA.generate(2048)

    def get_public_key(self):
        '''Get key to send to remote host'''
        return str(self.own_public_key.export_key("PEM"))

    def add_remote_key(self, key):
        '''Add the remote host's public key'''
        print(key[3:-2].replace('\\n','\n').replace('\\',''))
        self._remote_public_key=RSA.import_key(key[3:-2].replace('\\n','\n').replace('\\',''))

    def encrypt_remote(self, message):
        '''Encrypt the message using the remote host's public key'''
        cipher_rsa = PKCS1_OAEP.new(self._remote_public_key)
        return self.encode(message, cipher_rsa)

    def sign(self, message):
        '''Encrypt the message using own private key'''
        cipher_rsa = PKCS1_OAEP.new(self.own_private_key)
        return self.encode(message, cipher_rsa)

    def unsign(self, message):
        '''Decrypt a message signed with the remote host's public key'''
        cipher_rsa = PKCS1_OAEP.new(self._remote_public_key)
        return self.decode(message, cipher_rsa)

    def decrypt(self, message):
        '''Decrypt a message encrypted with own public key'''
        cipher_rsa = PKSC1_OAEP.new(self.own_private_key)
        return self.decode(message, cipher_rsa)

    def encode(self, message, key):
        message_blocks = []
        current_block = 1
        working_string = ""
        for i in range(len(message)):
            if i >= 190 * current_block:
                message_blocks.append(working_string)
                current_block += 1
                working_string = ""
            working_string += message[i]
        while len(working_string) < 190:
            working_string += ' '
        message_blocks.append(working_string)
        __message=[]
        for x in message_blocks:
            __message.append(key.encrypt(bytes(x, 'utf-8')))
        for y in __message:
            print(len(y))
        return json.dumps(str(__message))

    def decode(self, message, key):
         _message=json.loads(message)
         _message = message[3:-3]
         _message = _message[::-1]
         print(_message)
         _message_block = []
         current_block = 1
         working_string = ""
         for i in range(len(_message)):
            if i >= 256 * current_block:
                _message_block.append(working_string.replace('$%$', '\\'))
                current_block += 1
                working_string = ""
            if(not _message[i] == '\\'):
                working_string += _message[i]
            else:
                working_string += '$%$'
         _message_block.append(working_string.replace('$%$', '\\'))
         dec_message=""
         for x in _message_block:
             print(x)
         for x in _message_block:
            dec_message += str(key.decrypt(bytes(x, 'utf-8')))
         return dec_message

    def encrypt_all(self, message):
        '''Prepare a message for sending.'''
        return encrypt_remote(sign(message))

    def decrypt_all(self,message):
        '''Decrypt a double-encrypted message'''
        return unsign(decrypt(message))