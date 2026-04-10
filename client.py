import socket, struct, threading, sys, signal, os, random, base64, hashlib, hmac, tty, termios, string
from Crypto import Random
from Crypto.Cipher import AES,PKCS1_OAEP
from Crypto.PublicKey import RSA

ALLOWED = string.ascii_letters + string.digits + string.punctuation + " "

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

def write(text):
    sys.stdout.write(text)
    sys.stdout.flush()

class Linput():
    def lgetch(self):
        fd = sys.stdin.fileno()
        old_settings = termios.tcgetattr(fd)
        try:
            tty.setraw(sys.stdin.fileno())
            ch = sys.stdin.read(1)
        finally:
            termios.tcsetattr(fd, termios.TCSADRAIN, old_settings)
        return ch

    def linput(self):
       self.data = ''
       while True:
        ch = self.lgetch()

        if ch in ('\r', '\n'):
            if self.data:
                return self.data
        elif ch in ('\x08', '\x7f'):
            if len(self.data) > 0:
                print('\b \b', end="", flush=True)
                self.data = self.data[:-1]

        elif ch == '\x1b':

                second = self.lgetch()
                if second == '[':
                    while True:
                        next_ch = self.lgetch()
                        if next_ch.isalpha() or next_ch == '~':
                            break
                    continue
                elif second == 'O':
                    _ = self.lgetch()
                    continue
                else:
                    continue
        elif ch in ALLOWED:
            self.data += ch
            write(ch)

        else:
            continue

class Encryptor(object):
    def __init__(self):
        self.bs = AES.block_size
        self.iv = self.ranGen()
        self.aesKey = None #get from chat server
        self.macKey = None # get from chat server
        self.privateKey = RSA.generate(2048, Random.new().read)
        self.publicKey = self.privateKey.publickey()

    ranGen = lambda self: Random.new().read(self.bs)
    rsaEncrypt = lambda self,data:base64.b64encode(PKCS1_OAEP.new(self.publicKey).encrypt(data))
    rsaDecrypt = lambda self,enc_data: PKCS1_OAEP.new(self.privateKey).decrypt(base64.b64decode(enc_data))
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

    def decrypt(self,ciphertext):
        encrypted = bytes.fromhex(base64.b64decode(base64.b64decode(ciphertext)).decode('utf-8'))
        iv,ciphertext,tag = encrypted[0:16],encrypted[16:-32],encrypted[-32:]
        if self.macGen(ciphertext) == tag:
            chiper = AES.new(self.aesKey, AES.MODE_CBC, iv)
            return self.unpad(chiper.decrypt(ciphertext)).decode("utf-8")
        return ''

class Client(object):
    def __init__(self, server_ip="localhost", server_port=555):
        self.server_ip = server_ip
        self.server_port = server_port
        self.encryptor = Encryptor()
        self.linput = Linput()
        self.get_color = staticmethod(lambda:random.choice(['\033[1;30m', '\033[0;31m', '\033[1;31m', '\033[0;32m', '\033[1;32m', '\033[0;33m', '\033[1;33m', '\033[0;34m', '\033[1;34m', '\033[0;35m', '\033[1;35m', '\033[0;36m', '\033[1;36m', '\033[0;37m', '\033[1;37m']))
        self.color = self.get_color()
        self.done = False

    def connect(self):
        try:
            self.connection = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.connection.connect((self.server_ip, self.server_port))
            self.connection = SendRecv(self.connection)
        except:
           write("[!] The Chat Server is not Running right now!\n")
           sys.exit(1)
        status = self.connection.recv()
        if not status:
             sys.exit(0)
        while True:
            self.username = str(input("Enter Your Username: ")).strip()
            if not self.username:
                write('[!] Please Enter an username!\n')
                continue
            self.connection.send(self.username.encode("UTF-8"))
            status = self.connection.recv().decode('UTF-8')
            if status == ':ok':
                self.connection.send(self.encryptor.publicKey.exportKey(format='PEM'))
                self.encryptor.aesKey = self.encryptor.rsaDecrypt(self.connection.recv())
                self.encryptor.macKey = self.encryptor.rsaDecrypt(self.connection.recv())
                break
            else:
                   write(f'\n[!] {status}\n')
        server_msg = self.encryptor.decrypt(self.connection.recv())
        write(server_msg)
    def recver_write(self, msg):
            write('\n\033[1A\033[1K')
            write("\033[1A\033[2K\r"+msg+"\n\n")
            #write(f"\n\033[1A\033[2K\r{msg}\n\n")
            write("\r" + self.prompt + "".join(self.linput.data))
    def recver(self):
        while True:
            msg = self.connection.recv()
            if msg in [b':bye', b':serverbye', b':kick']:
               if msg == b":serverbye":
                    self.recver_write("[ CHAT SERVER ] Is Shutdown, type anything and press enter to exit.")
               elif msg == b':kick':
                     self.recver_write('[ CHAT SERVER ] You Were Kicked!')
               self.connection.sock.close()
               self.done = True
               break
            msg = self.encryptor.decrypt(msg)
            self.recver_write(msg)
    def start(self):
        self.connect()
        thread = threading.Thread(target=self.recver)
        thread.daemon = True
        thread.start()
        self.prompt = f"\033[1;37m\n\033[1A\033[2K[ {self.color}{self.username}\033[1;37m:< ] "
        while True:
          try:
            print(' ')
            write(self.prompt)
            msg = str(self.linput.linput()).strip()
            if not msg:
              write('\033[1A\033[2K')
              continue
            if msg == ':quit':
                self.connection.send(b':quit')
                while not self.done:
                    continue
                print(' ')
                break
            elif msg == ':who':
                self.connection.send(b':who')
                continue
            if self.done:
                 print(' ')
                 break
            msg = f'[ {self.username}:> ] {msg}'
            self.connection.send(self.encryptor.encrypt(msg))
            write('\n\033[1A\033[2K')
            write("\033[1A\033[2K"+msg+"\n")
          except:
              break
        sys.exit(0)
if __name__ == '__main__':
   os.system('clear')
   print("")
   client = Client()
   client.start()
