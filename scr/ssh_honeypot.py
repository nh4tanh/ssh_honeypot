import csv
import logging
import threading
from http.client import responses
from logging.handlers import RotatingFileHandler
import socket
import paramiko
from datetime import datetime
import json
import time

# Constants
logging_format = logging.Formatter('%(message)s')
SSH_BANNER = "SSH-2.0-MySSHServer_1.1"
host_key = paramiko.RSAKey(filename='../key/server.key')

# Loggers
auth_logger = logging.getLogger("Auth Logger")
auth_logger.setLevel(logging.INFO)
auth_handler = RotatingFileHandler("../log/auth.log", maxBytes=5 * 1024, backupCount=3)
auth_handler.setFormatter(logging_format)
auth_logger.addHandler(auth_handler)

alert_logger = logging.getLogger("Alerts Logger")
alert_logger.setLevel(logging.INFO)
alert_handler = RotatingFileHandler("../log/alerts.log", maxBytes=5 * 1024, backupCount=3)
alert_handler.setFormatter(logging_format)
alert_logger.addHandler(alert_handler)

# Dangerous command keywords
DANGEROUS_COMMANDS = ['rm', 'wget', 'curl', 'nc', 'nmap', 'scp', 'ssh']


def is_dangerous(cmd):
    return any(cmd.startswith(d) for d in DANGEROUS_COMMANDS)


def log_command(ip, username, command):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_line = f'[{timestamp}] [{ip}] [USERNAME: {username}] [CMD] {command}'
    auth_logger.info(log_line)

    with open("../log/cmd_logs.csv", 'a', newline='') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow([timestamp, ip, username, command])

    log_entry = {
        "timestamp": timestamp,
        "ip": ip,
        "username": username,
        "command": command
    }
    with open('../log/cmd_logs.json', 'a') as f:
        f.write(json.dumps(log_entry) + '\\n')

    if is_dangerous(command):
        alert_logger.warning(f"[{timestamp}] [DANGER] [{ip}] {command}")


# Emulated Shell

def emulated_shell(channel, client_ip, username):
    def send(text):
        channel.send(text.encode())

    def sendln_delay(text, delay=0.05):
        for line in text.splitlines():
            send((line + '\r\n').encode())
            time.sleep(delay)

    def sendln(text):
        channel.send(text.encode() + b'\r\n')

    fake_fs = {
        'custardA.config': 'CONFIG: allow_remote_root=1',
        'flag.txt': 'CTF{you_found_me}',
        'notes.txt': 'todo: upload backdoor\ncheck crontab'
    }

    prompt = 'custardA$ '
    command = ''
    history = []
    history_index = -1
    cursor_pos = 0

    send(prompt)

    while True:
        char = channel.recv(1)
        if not char:
            break

        # Handle arrow keys (escape sequence)
        if char == b'\x1b':
            seq = channel.recv(2)
            if seq == b'[A':  # Up
                if history:
                    history_index = max(0, history_index - 1)
                    command = history[history_index].decode()
                    cursor_pos = len(command)
                    send('\r\x1b[K' + prompt + command)
            elif seq == b'[B':  # Down
                if history:
                    history_index = min(len(history) - 1, history_index + 1)
                    command = history[history_index].decode()
                    cursor_pos = len(command)
                    send('\r\x1b[K' + prompt + command)
            elif seq == b'[C':  # Right
                if cursor_pos < len(command):
                    send('\x1b[C')
                    cursor_pos += 1
            elif seq == b'[D':  # Left
                if cursor_pos > 0:
                    send('\x1b[D')
                    cursor_pos -= 1
            continue

        # Backspace
        if char in (b'\x7f', b'\x08'):
            if cursor_pos > 0:
                command = command[:cursor_pos - 1] + command[cursor_pos:]
                cursor_pos -= 1
                send('\r\x1b[K' + prompt + command)
                send('\r' + prompt + command[:cursor_pos])
            continue

        # Enter
        if char == b'\r':
            send('\r\n')
            cmd = command.strip()
            if cmd:
                history.append(cmd.encode())
                history_index = len(history)

            if cmd == 'exit':
                sendln("Goodbye!")
                channel.close()
                break
            elif cmd == 'pwd':
                sendln('/usr/local')
            elif cmd == 'whoami':
                sendln(f'{username}')
            elif cmd == 'ls':
                sendln('custardA.config flag.txt')
            elif cmd == 'cat custardA.config':
                sendln('CONFIG: allow_remote_root=1')
            elif cmd == 'cat flag.txt':
                sendln('CTF{you_found_me}')

            elif cmd.startswith('cat '):
                filename = cmd.split(' ', 1)[1]
                if filename in fake_fs:
                    sendln(fake_fs[filename])
                else:
                    sendln(f"cat: {filename}: No such file or directory")

            elif cmd.startswith('touch '):
                filename = cmd.split(' ', 1)[1]
                fake_fs[filename] = ''
                sendln('')

            elif cmd.startswith('rm '):
                filename = cmd.split(' ', 1)[1]
                if filename in fake_fs:
                    del fake_fs[filename]
                    sendln('')
                else:
                    sendln(f"rm: cannot remove '{filename}': No such file")

            elif cmd.startswith('echo '):
                if '>' in cmd:
                    parts = cmd.split('>', 1)
                    content = parts[0].strip()[5:].strip().strip('"\'"')
                    filename = parts[1].strip()
                    fake_fs[filename] = content
                    sendln('')
                else:
                    sendln(cmd[5:])

            elif cmd.startswith('mkdir '):
                dirname = cmd.split(' ', 1)[1]
                sendln(f"mkdir: cannot create directory '{dirname}': Permission denied")

            elif cmd == 'ls':
                sendln(' '.join(fake_fs.keys()))

            elif cmd == 'uname -a':
                sendln('Linux ubuntu 5.15.0-67-generic #74-Ubuntu SMP x86_64 GNU/Linux')

            elif cmd == 'uptime':
                sendln('14:25:03 up  2:14,  2 users,  load average: 0.01, 0.05, 0.10')

            elif cmd == 'id':
                sendln('uid=0(root) gid=0(root) groups=0(root)')

            elif cmd == 'ifconfig' or cmd == 'ip a':
                sendln('eth0: inet 192.168.56.101 netmask 255.255.255.0 broadcast 192.168.56.255')

            elif cmd == 'netstat -tulnp':
                sendln('tcp   0  0 0.0.0.0:22    0.0.0.0:*    LISTEN 1234/sshd')

            elif cmd == 'ps aux':
                sendln('root      1  0.0  0.1  22504  1584 ?  Ss   09:04   0:01 /sbin/init')

            elif cmd == 'df -h':
                sendln('/dev/sda1        40G   15G   23G  40% /')

            elif cmd == 'env':
                sendln('PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin')

            elif cmd == 'history':
                for i, h in enumerate(history[-10:], 1):
                     sendln(f'{i}  {h.decode()}')

            elif cmd.startswith('wget ') or cmd.startswith('curl '):
                sendln_delay('Connecting to malicious.server... 200 OK\nSaving file to disk... done.')

            elif cmd.startswith('nano ') or cmd.startswith('vi ') or cmd.startswith('vim '):
                sendln('[!] nano is not supported in this terminal.')
                sendln('Use `cat`, `echo`, or `touch` instead.')

            elif cmd == r'echo "<?php system(\$_GET[\'cmd\']); ?>" > shell.php':
                fake_fs['shell.php'] = r'<?php system(\$_GET[\'cmd\']); ?>'
                sendln('shell.php created.')

            elif cmd == '':
                pass
            else:
                sendln(f"bash: {cmd}: command not found")

            log_command(client_ip, username=username, command=cmd)
            command = ''
            cursor_pos = 0
            send(prompt)
            continue

        # Normal character
        command = command[:cursor_pos] + char.decode() + command[cursor_pos:]
        cursor_pos += 1
        send('\r\x1b[K' + prompt + command)
        send('\r' + prompt + command[:cursor_pos])


# SSH Server
class Server(paramiko.ServerInterface):
    def __init__(self, client_ip, input_username, input_passwd, creds_dict = None):
        self.event = threading.Event()
        self.client_ip = client_ip
        self.input_username = input_username
        self.input_passwd = input_passwd
        self.creds_dict = creds_dict

    def check_channel_request(self, kind, chanid):
        if kind == 'session':
            return paramiko.OPEN_SUCCEEDED

    def get_allowed_auths(self, username):
        return 'password'

    def check_auth_password(self, username, password):
        auth_logger.info(
            f'Client {self.client_ip} attempted connection with username: {username}, password: {password}')
        alert_logger.info(f'{self.client_ip}, {username}, {password}')
        if self.input_username and self.input_passwd:
            return paramiko.AUTH_SUCCESSFUL if username == self.input_username and password == self.input_passwd else paramiko.AUTH_FAILED
        elif self.creds_dict and username in self.creds_dict:
            if self.creds_dict[username] == password:
                return paramiko.AUTH_SUCCESSFUL
            else:
                return paramiko.AUTH_FAILED
        else:
            return paramiko.AUTH_FAILED

    def check_channel_shell_request(self, channel):
        self.event.set()
        return True

    def check_channel_pty_request(self, channel, term, width, height, pixelwidth, pixelheight, modes):
        return True

    def check_channel_exec_request(self, channel, command):
        return True


# Handle client

def client_handle(client, addr, username, password, creds_dict):
    client_ip = addr[0]
    print(f'{client} has connected to server!!!')

    try:
        transport = paramiko.Transport(client)
        transport.local_version = SSH_BANNER
        server = Server(client_ip=client_ip, input_username=username, input_passwd=password)

        transport.add_server_key(host_key)
        transport.start_server(server=server)

        channel = transport.accept(100)
        if channel is None:
            print('No channel is open.')
            return

        banner = 'Welcome to Ubuntu 22.04 LTS (Yomama)!\r\n\r\n'
        channel.send(banner.encode())
        emulated_shell(channel, client_ip, username)

    except Exception as error:
        print(error)
    finally:
        try:
            transport.close()
        except:
            pass
        client.close()


# Run honeypot

def honey_pot(address, port, username, password, creds_dict=None):
    socks = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    socks.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    socks.bind((address, port))

    socks.listen(100)
    print(f"SSH server is listening on port {port}.")

    while True:
        try:
            client, addr = socks.accept()
            ssh_honeypot_thread = threading.Thread(target=client_handle, args=(client, addr, username, password))
            ssh_honeypot_thread.start()
        except Exception as error:
            print("!!! Exception - Could not open new client connection !!!")
            print(error)


honey_pot('127.0.0.1', 2223, 'username', 'password')
