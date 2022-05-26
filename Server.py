import json
import crypt
import SocketPair
import Cryptography

class Server:
    def __init__(self,filepath,timestamper, ca):
        self._allUsers=json.load(open(filepath))
        self._filepath=filepath
        self._timestamper=timestamper
        self._keypair=Cryptography.SecureConnection()
        self._badpass=0
        self._ca=ca
        self._crypto_enabled=True
        self._currentUser=""

    def openUserFile(self,file):
        userfile=json.loads(open(file,"rt").read())
        self._allUsers=userfile

    def saveUserFile(self):
        value=self._allUsers
        json.dump(value, open(self._filepath, "wt"), ensure_ascii=False)

    def addUser(self,name,email,password):
        try:
            if email in self._allUsers:
                return False
            self._allUsers[email]={"Name": name, "Password": crypt.crypt(password, email), "Contacts": {}, "Files": {}}
            self.saveUserFile()
            return True
        except:
            return False

    def loginUser(self,email,password):
        try:
            if self._badpass>3:
                return False
            if email not in self._allUsers:
                return False
            account=self._allUsers[email]
            if not account["Password"]==crypt.crypt(password, email):
                self._badpass=self._badpass+1
                return False
            self._badpass=0
            self._currentUser=email
            self._allUsers[email]["Connected"]=True
            self.saveUserFile()
            return True
        except:
            return False

    def ListContacts(self):
        try:
            value={}
            me=self._currentUser
            self.openUserFile(self._filepath)
            for x in self._allUsers[me]["Contacts"]:
                if me in self._allUsers[x]["Contacts"]:
                    value[x]={"Display Name":self._allUsers[me]["Contacts"][x]["Display Name"], "Connected":self._allUsers[x]["Connected"]}
            return value
        except:
            return {}

    def AddContact(self, contact_email, contact_name):
        try:
            self.openUserFile(self._filepath)
            self._allUsers[self._currentUser]["Contacts"][contact_email]={"Display Name": contact_name}
            self.saveUserFile()
            return True
        except:
            return False

    def HandleClientInput(self,mode,str):
        if(mode==SocketPair.MODE_ESTABLISH_CONNECTION):
            if(self._crypto_enabled):
                self._keypair.add_remote_key(str)
                value={"Public Key": self._keypair.get_public_key(), "Certificate": self._ca.issue_certificate("Secure Drop")}
                self.SendToClient(SocketPair.MODE_ESTABLISH_CONNECTION, value)
            else:
                self.SendToClient(SocketPair.MODE_ESTABLISH_CONNECTION, {})
        else:
            _str=str
            if(self._crypto_enabled):
                _str=self._keypair.decrypt_all(str)
            dct=json.loads(_str)
            if(not self._crypto_enabled
                or self._timestamper.checkStamp(dct)):
                if(mode==SocketPair.MODE_USER_REGISTER_REQUEST):
                    try:
                        status=self.addUser(dct["Name"], dct["Email"], dct["Password"])
                        value={}
                        value["Success"]=status
                        self.SendToClient(SocketPair.MODE_USER_REGISTER_RESPONSE,value)
                    except:
                        self.SendToClient(SocketPair.MODE_USER_REGISTER_RESPONSE,{"Success":False})
                elif(mode==SocketPair.MODE_USER_LOGIN_REQUEST):
                    try:
                        status=self.loginUser(dct["Email"], dct["Password"])
                        value={"Success": status, "Name" : self._allUsers[dct["Email"]]["Name"] }
                        self.SendToClient(SocketPair.MODE_USER_LOGIN_RESPONSE, value)
                    except:
                        self.SendToClient(SocketPair.MODE_USER_LOGIN_RESPONSE, {"Success":False})
                elif(mode==SocketPair.MODE_ADD_CONTACT_REQUEST):
                    try:
                        status=self.AddContact(dct["Email"], dct["Name"])
                        value = {"Success": status}
                        self.SendToClient(SocketPair.MODE_ADD_CONTACT_RESPONSE, value)
                    except:
                        self.SendToClient(SocketPair.MODE_ADD_CONTACT_RESPONSE, {"Success": False})
                elif(mode==SocketPair.MODE_VIEW_CONTACT_REQUEST):
                    #Send contact data for all contacts.
                    try:
                        value={"Success":True, "Contacts": self.ListContacts()}
                        self.SendToClient(SocketPair.MODE_VIEW_CONTACT_RESPONSE, value)
                    except:
                        self.SendToClient(SocketPair.MODE_VIEW_CONTACT_RESPONSE, {"Success":False})
                elif(mode==SocketPair.MODE_UPLOAD_FILE_REQUEST):
                    #Upload a file.
                    try:
                        self.openUserFile(self._filepath)
                        self._allUsers[self._currentUser]["Files"][dct["Filename"]]=dct["Contents"]
                        self.saveUserFile()
                        self.SendToClient(SocketPair.MODE_UPLOAD_FILE_RESPONSE, {"Success":True})
                    except:
                        self.SendToClient(SocketPair.MODE_UPLOAD_FILE_RESPONSE, {"Success":False})
                elif(mode==SocketPair.MODE_AUTHORIZE_FILE_REQUEST):
                    #Authorize a contact to download a file.
                    try:
                        if(dct["Recipient"] in self._allUsers[self._currentUser]["Contacts"]):
                            if(self._currentUser in self._allUsers[dct["Recipient"]]["Contacts"]):
                                if(dct["Filename"] in self._allUsers[self._currentUser]["Files"]):
                                    self.openUserFile(self._filepath)
                                    self._allUsers[dct["Recipient"]]["Files"][self._currentUser+":"+dct["Filename"]]=self._allUsers[self._currentUser]["Files"][dct["Filename"]]
                                    self.saveUserFile()
                                    self.SendToClient(SocketPair.MODE_AUTHORIZE_FILE_RESPONSE, {"Success":True})
                                else:
                                    self.SendToClient(SocketPair.MODE_AUTHORIZE_FILE_RESPONSE, {"Success":False, "Message":"File does not exist!"})
                            else:
                                self.SendToClient(SocketPair.MODE_AUTHORIZE_FILE_RESPONSE, {"Success":False, "Message":"Contact request not yet accepted!"})
                        else:
                            self.SendToClient(SocketPair.MODE_AUTHORIZE_FILE_RESPONSE, {"Success":False, "Message":"Recipient is not yet a contact!"})
                    except:
                        self.SendToClient(SocketPair.MODE_AUTHORIZE_FILE_RESPONSE, {"Success":False, "Message":"Unknown error!"})
                elif(mode==SocketPair.MODE_DOWNLOAD_FILE_REQUEST):
                    #Check whether the user is allowed to download this file. If they are, send the file.
                    try:
                        self.openUserFile(self._filepath)
                        if(dct["Filename"] in self._allUsers[self._currentUser]["Files"]):
                            self.SendToClient(SocketPair.MODE_DOWNLOAD_FILE_RESPONSE, {"Success":True, "File Contents":self._allUsers[self._currentUser]["Files"][dct["Filename"]]})
                        else:
                            self.SendToClient(SocketPair.MODE_DOWNLOAD_FILE_RESPONSE, {"Success":False})
                    except:
                        self.SendToClient(SocketPair.MODE_DOWNLOAD_FILE_RESPONSE,{"Success":False})
                elif(mode==SocketPair.MODE_CLOSE_CONNECTION):
                    try:
                        self.openUserFile(self._filepath)
                        self._allUsers[self._currentUser]["Connected"]=False
                        self.saveUserFile()
                    finally:
                        self.SendToClient(SocketPair.MODE_CLOSE_CONNECTION,{})
                        self._currentUser=""

                elif(mode==SocketPair.MODE_LIST_FILES_REQUEST):
                    try:
                        self.openUserFile(self._filepath)
                        value=[]
                        for x in self._allUsers[self._currentUser]["Files"]:
                            value.append(x)
                        self.SendToClient(SocketPair.MODE_LIST_FILES_RESPONSE, {"Success":True, "Files":value})
                    except:
                        self.SendToClient(SocketPair.MODE_LIST_FILES_RESPONSE, {"Success":False})

    def SendToClient(self,mode,dct):
        _dct=dct
        _str=json.dumps(_dct, ensure_ascii=False)
        if(mode!=SocketPair.MODE_ESTABLISH_CONNECTION):
            if(self._crypto_enabled):
                self._timestamper.stamp(_dct)
                _str=self._keypair.encrypt_all(json.dumps(_dct, ensure_ascii=False))
        self._RemoteHost.ServerSendToClient(mode,_str)
