import Server
import Client
import CA
import SocketPair
import Cryptography
import datetime

def main():
    #Start simulated hosts.
    ca=CA.CA(datetime.timedelta(0,2,0,0,0,0,0),128)
    server=Server.Server("./Users.json",Cryptography.Timestamper(datetime.timedelta(0,2,0,0,0,0,0),128),ca)
    ca.certify("Secure Drop", server._keypair.get_public_key())
    client=Client.Client("./ClientData.json",Cryptography.Timestamper(datetime.timedelta(0,2,0,0,0,0,0),128),ca)
    pair=SocketPair.SocketPair(server, client)
    #DEBUG: Disable cryptography.
    server._crypto_enabled=False
    client._crypto_enabled=False

    #Start client execution.
    client.run()

main()