import Cryptography
import json

class CA:
    def __init__(self, delay, nonce_width):
        self._timestamper=Cryptography.Timestamper(delay, nonce_width)
        self.keypair=Cryptography.SecureConnection()
        self.certificates={}

    def certify(self, hostname, key):
        self.certificates[hostname]=key

    def issue_certificate(self, hostname):
        value={}
        if hostname in self.certificates:
            value={"Success": True, "Host": hostname, "Key": self.certificates[hostname]}
        else:
            value={"Success": False, "Host": hostname, "Key" : "Not found!"}
        self._timestamper.stamp(value)
        return self.keypair.sign(json.dumps(value["Key"][26:-24].replace("\n", ""), ensure_ascii=False))

    def get_public_key(self):
        return self.keypair.get_public_key()


