import threading

MODE_ESTABLISH_CONNECTION=0
MODE_USER_REGISTER_REQUEST=1
MODE_USER_REGISTER_RESPONSE=2
MODE_USER_LOGIN_REQUEST=3
MODE_USER_LOGIN_RESPONSE=4
MODE_ADD_CONTACT_REQUEST=5
MODE_ADD_CONTACT_RESPONSE=6
MODE_VIEW_CONTACT_REQUEST=7
MODE_VIEW_CONTACT_RESPONSE=8
MODE_UPLOAD_FILE_REQUEST=9
MODE_UPLOAD_FILE_RESPONSE=10
MODE_AUTHORIZE_FILE_REQUEST=11
MODE_AUTHORIZE_FILE_RESPONSE=12
MODE_DOWNLOAD_FILE_REQUEST=13
MODE_DOWNLOAD_FILE_RESPONSE=14
MODE_CLOSE_CONNECTION=15
MODE_LIST_FILES_REQUEST=16
MODE_LIST_FILES_RESPONSE=17

class SocketPair:
    def __init__(self, server, client):
        self._server=server
        self._client=client
        server._RemoteHost=self
        client._RemoteHost=self

    def ClientSendToServer(self,mode,str):
        self._server.HandleClientInput(mode,str)

    def ServerSendToClient(self,mode,str):
        self._client.HandleServerInput(mode,str)


