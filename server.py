import socket, threading, sys, os, signal, time, re, struct, base64, hashlib, hmac
from Crypto import Random
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA
from collections import OrderedDict as odict

COMMANDS = odict([('help', 'Shows this help'),
                  ('clear', 'clear the screen'),
                  ('brodcast <msg>', 'broadcast a msg as the server to the clients'),
                  ('list', 'Lists connected clients'),
                  ('banned', 'Lists banned IPs'),
                  ('kick <username>', 'kick an user from the chat'),
                  ('ban <ip>', 'Ban an ip address'),
                  ('unban <ip>', 'Unban an ip address'),
                  ('shutdown', 'Shuts server down')])
class SendRecv:
    def __init__(self,sock):
        self.sock = sock
    def send(self, data):
        pkt = struct.pack('>I', len(data)) + data
        self.sock.sendall(pkt)
    def recv(self):
        pktlen = self.recvall(4)
        if not pktlen: return ""
        pktlen = struct.unpack('>I', pktlen)[0]
        return self.recvall(pktlen)
    def recvall(self, n):
        packet = b''
        while len(packet) < n:
            frame = self.sock.recv(n - len(packet))
            if not frame:return None
            packet += frame
        return packet
class Encryptor(object):
    def __init__(self):
        self.bs = AES.block_size
        self.iv = self.ranGen()
        self.aesKey = hashlib.sha256(str(RSA.generate(2048, Random.new().read)).encode('utf-8')).digest()
        self.macKey = self.ranGen()

    ranGen = lambda self: Random.new().read(self.bs)
    rsaEncrypt = lambda self,data,client_public_key:base64.b64encode(PKCS1_OAEP.new(client_public_key).encrypt(data))
    pad = lambda self,data: data + (self.bs - len(data) % self.bs) * chr(self.bs - len(data) % self.bs)
    unpad = staticmethod(lambda data: data[:-ord(data[len(data)-1:])])
    macGen = lambda self,ciphertext: hmac.new(self.macKey, msg=ciphertext, digestmod=hashlib.sha256).digest()

    def encrypt(self, raw):
        raw = self.pad(raw)
        cipher = AES.new(self.aesKey,AES.MODE_CBC, self.iv)
        ciphertext = cipher.encrypt(raw.encode('utf-8'))
        tag = self.macGen(ciphertext)
        encrypted = self.iv+ciphertext+tag
        self.iv = self.ranGen()
        return base64.b64encode(base64.b64encode(encrypted.hex().encode('utf-8')))


class ChatServer(object):
    def __init__(self, host="localhost", port=555):
        self.encryptor = Encryptor()
        self.host = host
        self.port = port
        self.clients = dict()
        self.banedIPs = list()
        self.socket = None
        self.done = False

    def print_help(self):
        print(' ')
        layout = "  {!s:20} {!s:10} "
        print(layout.format(*['Command', 'Description']))
        print(layout.format(*['~~~~~~~', '~~~~~~~~~~~']))
        for com,des in COMMANDS.items():
            print(layout.format(*[com,des]))
        print(' ')
        return

    def register_signal_handler(self):
        signal.signal(signal.SIGINT, self.shutdown)
        signal.signal(signal.SIGTERM, self.shutdown)
        return

    def shutdown(self, sig, frame):
        self.done = True
        for username,connection in self.clients.items():
            try:
                connection[0].send(b':serverbye')
                connection[0].sock.shutdown(2)
                connection[0].sock.close()
            except Exception as e:
                print(f"[!] Could not close connection of {username} Error: {e} !!!")
        self.socket.close()
        time.sleep(1.5)
        print('  [!] Server has been shutdown!')
        sys.exit(0)

    def socket_create(self):
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        except socket.error as msg:
            print(f"[!] Socket creation error: {msg} !!!")
            sys.exit(1)
        return

    def socket_bind(self):
        try:
            self.socket.bind((self.host, self.port))
            self.socket.listen()
        except socket.error as e:
            print(f"[!] Socket binding error: {e} !!!")
            time.sleep(5)
            self.socket_bind()
        return

    def accept_connections(self):
        while not self.done:
            try:
                connection, address = self.socket.accept()
                if address[0] in self.banedIPs:
                    print(f"[!] Rejected banned IP: {address[0]}")
                    connection.close()
                    continue
                connection = SendRecv(connection)
                print(f'\n[*] Connection has been established: {address[0]}:{address[1]}')
                connection.send(b':ok')
                currrent_usernames = {user.lower() for user in self.clients.keys()}
                while True:
                    client_username = connection.recv().decode('UTF-8')
                    if client_username.lower() in currrent_usernames:
                        connection.send(b'Nickname is already in use!')
                        continue
                    if not (3 <= len(client_username) <= 15):
                        connection.send(b'Nickname must be 3-15 characters long.!')
                        continue

                    if not re.match(r'^[A-Za-z0-9_]+$', client_username):
                        connection.send(b'Nickname can only contain letters, numbers, and underscores.!')
                        continue
                    break
                connection.send(b':ok')
                client_public_key = RSA.import_key(connection.recv().decode('UTF-8'))
                connection.send(self.encryptor.rsaEncrypt(self.encryptor.aesKey, client_public_key))
                connection.send(self.encryptor.rsaEncrypt(self.encryptor.macKey, client_public_key))
                connection.send(self.encryptor.encrypt("=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\n\tWelcome to ChatHub\n=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=\nenter ':quit' to leave the chat, ':who' to see the connected users\n\n"))
                self.brodcast(self.encryptor.encrypt(f"[ CHAT SERVER ] {client_username} has join the chat."), connection)
            except Exception as e:
                print(f'[!] Error accepting connections: {e} !!!')
                continue
            thread = threading.Thread(target=self.user_handle, args=(client_username, connection, address))
            thread.daemon = True
            thread.start()
        return

    def user_handle(self, username, connection, address):
        print(f'\n{username} from {address[0]}:{address[1]} has Conncted!')
        self.clients[username]=[connection, address]
        while not self.done:
            try:
              msg = connection.recv()
            except:
                 break
            if msg:
             if msg == b":quit":
                self.user_disconnect(username, connection)
                break
             elif msg == b':who':
                  connection.send(self.encryptor.encrypt('[ Connected Users ] '+', '.join(self.clients.keys())))
             else:
                 #print(f"\n{username} ==>  {msg}\n")
                 self.brodcast(msg, connection)
             if self.done:
                    break

    def user_disconnect(self, username, connection, kicked=False):
        print(f"{username} from {self.clients[username][1][0]}:{self.clients[username][1][1]} {'discneected' if not kicked else 'kicked'}!")
        for user,conn in self.clients.items():
            if conn[0] != connection:
                conn[0].send(self.encryptor.encrypt(f"[ CHAT SERVER ] {username} {'has left the chat' if not kicked else 'has bean kicked!'}"))
        connection.send(b':bye')
        connection.sock.close()
        del self.clients[username]

    def brodcast(self, msg, connection):
        for user,conn in self.clients.items():
            if conn[0] != connection:
                conn[0].send(msg)

    def list_clients(self):
        if not self.clients:
            print("\n[!] There is no clients yet!\n")
            return
        print(' ')
        layout = "{!s:20} {!s:21}"
        print(layout.format(*['Username', 'Address']))
        print(layout.format(*['~~~~~~~~', '~~~~~~~']))

        for user in self.clients.keys():
            addr = "{}:{}".format(self.clients[user][1][0], self.clients[user][1][1])
            print(layout.format(*[user, addr]))
        print(' ')

    def kick_user(self, username):
        try:
            self.clients[username][0].send(b":kick")
        except:
            pass
        self.user_disconnect(username,self.clients[username][0], kicked=True)
        print(f"[!] Kicked {username}")

    def cli(self):
        print("*** Welcome to chatserver ***")
        print("type 'help' to see commands ")
        while True:
            cmd = str(input("ChatServer> ")).strip()
            if not cmd:
                continue
            elif cmd == 'help':
                self.print_help()
            elif cmd == 'clear':
                os.system('clear')
            elif cmd == 'shutdown':
                print("[~] Server is stopping ...")
                self.shutdown(1,2)
                break
            elif cmd == "list":
                self.list_clients()
            elif cmd == 'banned':
                if not self.banedIPs:
                    print('[!] There is no banned IPs !')
                    continue
                print('\n  Banned IPs\n  ~~~~~~~~~~')
                for ip in self.banedIPs:
                    print(f'  {ip}  ')
                print(' ')
            elif cmd.startswith('ban'):
                 parse = cmd.split(' ')
                 if len(parse) == 1:
                     print("Usage: ban <ip> e.g: ban 192.168.1.6")
                 else:
                     ip = parse[1]
                     if not re.match(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                                      r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                                      r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                                      r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', ip):
                         print(f'[!] Error: Invalid ipv4: {ip}')
                     else:
                         self.banedIPs.append(ip)
                         print(f'[*] IP:{ip} is banned from connect to the server\n')
            elif 'unban' in cmd:
              parse = cmd.split(' ')
              if len(parse) == 1:
                print('Usage: unban <banned IP> e.g: unban 192.168.1.6')
              else:
                ip = parse[1].strip()
                if not re.match(r'\b(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.' \
                                r'(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b', ip):

                    print(f'[!] Error: Invalid ipv4: {ip}')
                    continue
                if not ip in self.banedIPs:
                  print(f'[!] IP: {ip} is not banned!')
                else:
                  self.banedIPs.remove(ip)
                  print(f'[*] IP:{ip} can connect to the server now!')
            elif 'kick' in cmd:
                 parse = cmd.split(' ')
                 if len(parse) == 1:
                     print("Usage: kick <username> e.g: kick jack")
                 else:
                   username = parse[1].strip()
                   if not username in self.clients.keys():
                       print('[!] Unknown username!')
                   else:
                      self.kick_user(username)
            elif 'brodcast' in cmd:
                parse = cmd.split(maxsplit=1)
                if len(parse) == 1:
                    print("Usage: brodcast <message> e.g: brodcast hello guys this is a msg by the chat server")
                else:
                   if self.clients:
                        msg = f'[ CHAT SERVER ] {parse[1]}'
                        self.brodcast(self.encryptor.encrypt(msg), self.socket)
                        print('[*] Message sent to the clients!')
                   else:
                       print('[!] There is no clients to send this to!')
def Main():
    server = ChatServer()
    server.register_signal_handler()
    server.socket_create()
    server.socket_bind()
    t = threading.Thread(target=server.accept_connections)
    t.daemon = True
    t.start()
    server.cli()


if __name__ == '__main__':
    Main()
