import json
import SocketPair
import threading
import crypt
import Cryptography
import getpass

class Client:
    def __init__(self, filepath, timestamper, ca):
        self._nonces=[]
        self._filepath=filepath
        self._timestamper=timestamper
        self._connection=Cryptography.SecureConnection()
        self._ca=ca
        self._crypto_enabled=True;
        self.ca_key=Cryptography.SecureConnection()


    def RegisterUser(self):
        username = input("Enter Full Name: ")
        email = input("Enter Email Address: ")
        password = getpass.getpass(prompt = "Enter Password: ")
        repass = getpass.getpass(prompt = "Re-enter Password: ")
        while (password != repass):
            print("Passwords do not match.")
            repass = getpass.getpass(prompt = "Re-enter Password: ")
            print("Passwords Match.")
        user = {}
        user["Name"]=username
        user["Email"]=email
        user["Password"]=password
        self.SendToServer(SocketPair.MODE_USER_REGISTER_REQUEST, user)

    def Login(self):
        username=input("Enter Email Address: ")
        password=getpass.getpass(prompt="Enter Password: ")
        user={"Email": username, "Password": password}
        self.SendToServer(SocketPair.MODE_USER_LOGIN_REQUEST, user)

    def AddContact(self):
        username=input("Enter Email of new contact:")
        dispname=input("Enter display name of new contact:")
        self.SendToServer(SocketPair.MODE_ADD_CONTACT_REQUEST, {"Email":username, "Name": dispname})

    def UploadFile(self):
        local_filename=input("Enter path of file on this machine.")
        remote_filename=input("Enter display name of file.")
        file=open(local_filename, "rt").read()
        self.SendToServer(SocketPair.MODE_UPLOAD_FILE_REQUEST, {"Filename":remote_filename, "Contents":file})

    def ListContacts(self):
        self.SendToServer(SocketPair.MODE_VIEW_CONTACT_REQUEST, {})

    def AuthorizeFile(self):
        filename=input("Enter display name of file.")
        recipient=input("Enter email of contact to send file.")
        self.SendToServer(SocketPair.MODE_AUTHORIZE_FILE_REQUEST, {"Recipient":recipient, "Filename":filename})

    def DownloadFile(self):
        remote_filename=input("Enter display name of file. If this is not your file, it has the sender's email appended to the front, and separated with a \":\".")
        self.SendToServer(SocketPair.MODE_DOWNLOAD_FILE_REQUEST, {"Filename": remote_filename})

    def ListFiles(self):
        self.SendToServer(SocketPair.MODE_LIST_FILES_REQUEST, {})

    def HandleServerInput(self,mode,str):
        if(mode==SocketPair.MODE_ESTABLISH_CONNECTION):
            if(self._crypto_enabled):
                _str=json.loads(str)
                certificate=json.loads(self.ca_key.unsign(_str["Certificate"]))
                if (self._timestamper.checkStamp(certificate) 
                and certificate["Success"]
                and certificate["Host"]=="Secure Drop" 
                and certificate["Key"]==_str["Public Key"]):
                    self._connection.add_remote_key(_str["Public Key"])
                else:
                    print("Unable to establish identity of server.")
                    exit(0)
        else:
            _str=str
            if(self._crypto_enabled):
                _str=self._connection.decrypt_all(str)
            dct=json.loads(_str)
            if(not self._crypto_enabled
                or self._timestamper.checkStamp(dct)):
                if(mode==SocketPair.MODE_USER_REGISTER_RESPONSE):
                    if(dct["Success"]):
                        print("User Registered.")
                    else:
                        print("Registration Failed.")
                elif(mode==SocketPair.MODE_USER_LOGIN_RESPONSE):
                    if (dct["Success"]):
                        print("Welcome to Secure Drop, "+dct["Name"])
                    else:
                        print("Email and Password Combination Invalid.")
                elif(mode==SocketPair.MODE_ADD_CONTACT_RESPONSE):
                    if (dct["Success"]):
                        print("Contact added!")
                    else:
                        print("Sorry, something went wrong.")
                elif(mode==SocketPair.MODE_AUTHORIZE_FILE_RESPONSE):
                    if(dct["Success"]):
                        print("File sent!")
                    else:
                        print(dct["Message"])
                elif(mode==SocketPair.MODE_DOWNLOAD_FILE_RESPONSE):
                    if(dct["Success"]):
                        local_filename=input("Enter local filepath for file.")
                        open(local_filename,"w").write(dct["Contents"])
                    else:
                        print(dct["Message"])
                elif(mode==SocketPair.MODE_UPLOAD_FILE_RESPONSE):
                    if(dct["Success"]):
                        print("File uploaded!")
                    else:
                        print("Sorry, something went wrong.")
                elif(mode==SocketPair.MODE_VIEW_CONTACT_RESPONSE):
                    if(dct["Success"]):
                        for x in dct["Contacts"]:
                            print(dct["Contacts"][x]["Display Name"]+":"+x+":"+self.onlineMessage(dct["Contacts"][x]["Connected"]))
                        print("-----------------------------------------")
                    else:
                        print("Sorry, something went wrong.")
                elif(mode==SocketPair.MODE_CLOSE_CONNECTION):
                    exit(0)
                elif(mode==SocketPair.MODE_LIST_FILES_RESPONSE):
                    if(dct["Success"]):
                        for x in dct["Files"]:
                            print(x)
                    print("---------------------------------------------")

    def onlineMessage(self, value):
        if(value):
            return "Online"
        else:
            return "Offline"

    def quit(self):
        self.SendToServer(SocketPair.MODE_CLOSE_CONNECTION, {})

    def SendToServer(self,mode,dct):
        _dct=dct
        _str=json.dumps(dct, ensure_ascii=False)
        if(mode!=SocketPair.MODE_ESTABLISH_CONNECTION):
            if(self._crypto_enabled):
                self._timestamper.stamp(_dct)
                _str=self._connection.encrypt_all(json.dumps(_dct, ensure_ascii=False))
        self._RemoteHost.ClientSendToServer(mode,_str)
        
    def Help(self):
        print("\t\"help\" -> Show available commands")
        print("\t\"register\" -> Register a new account")
        print("\t\"login\" -> Log in to an existing account")
        print("\t\"add\" -> Add a new contact")
        print("\t\"list\" -> List all online contacts")
        print("\t\"send\" -> Transfer file to contact")
        print("\t\"upload\" -> Upload a file to the drop")
        print("\t\"download\" -> Download a file from the drop")
        print("\t\"files\" -> List files that can be downloaded")
        print("\t\"exit\" -> Exit SecureDrop")


    def run(self):
        runmodes={"register": self.RegisterUser, "login": self.Login, "help": self.Help, "add":self.AddContact, "list":self.ListContacts, "send":self.AuthorizeFile, "upload":self.UploadFile, "download":self.DownloadFile, "exit":self.quit}
        self.SendToServer(SocketPair.MODE_ESTABLISH_CONNECTION, self._connection.get_public_key())
        if not self._crypto_enabled:
            self.ca_key.add_remote_key(self._ca.get_public_key())
        #Main program loop.
        while(True):
            #Get run mode.
            user_input=input("secure_drop> ").lower()
            if user_input in runmodes:
                x=threading.Thread(target=runmodes[user_input](), args=[])
                x.start()
                x.join()
