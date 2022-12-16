#!/bin/bash
# UNBUNTU 20X64
# Version: 2023

# go to root
cd

# disable ipv6
echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6
sed -i '$ i\echo 1 > /proc/sys/net/ipv6/conf/all/disable_ipv6' /etc/rc.local

# install wget and curl
apt-get update; apt-get -y install wget curl;
apt-get install net-tools python -y

# set time GMT +7
ln -fs /usr/share/zoneinfo/Asia/Manila /etc/localtime

vps_ip=$(curl -s https://api.ipify.org)
#change this according to your SSH Account details
USER="teamworkvpn"
PASS="wasalack22"

###Instaling Python
/bin/cat <<"EOM" >/usr/local/sbin/socks.py
import socket, threading, thread, select, signal, sys, time, getopt

# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 80

PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:143'
RESPONSE = 'HTTP/1.1 101 Switching Protocol \r\n\r\n'


class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = 80
                port = 8080
                port = 8799
                port = 3128

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT

    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):

    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"

    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()

    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
EOM
chmod +x /usr/local/sbin/socks.py
screen -dmS socks python /usr/local/sbin/socks.py

###Instaling Python
/bin/cat <<"EOM" >/usr/local/sbin/socks2.py
import socket, threading, thread, select, signal, sys, time, getopt

# CONFIG
LISTENING_ADDR = '0.0.0.0'
LISTENING_PORT = 8118

PASS = ''

# CONST
BUFLEN = 4096 * 4
TIMEOUT = 60
DEFAULT_HOST = '127.0.0.1:555'
RESPONSE = 'HTTP/1.1 101 Switching Protocol \r\n\r\n'


class Server(threading.Thread):
    def __init__(self, host, port):
        threading.Thread.__init__(self)
        self.running = False
        self.host = host
        self.port = port
        self.threads = []
        self.threadsLock = threading.Lock()
        self.logLock = threading.Lock()

    def run(self):
        self.soc = socket.socket(socket.AF_INET)
        self.soc.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.soc.settimeout(2)
        self.soc.bind((self.host, self.port))
        self.soc.listen(0)
        self.running = True

        try:
            while self.running:
                try:
                    c, addr = self.soc.accept()
                    c.setblocking(1)
                except socket.timeout:
                    continue

                conn = ConnectionHandler(c, self, addr)
                conn.start()
                self.addConn(conn)
        finally:
            self.running = False
            self.soc.close()

    def printLog(self, log):
        self.logLock.acquire()
        print log
        self.logLock.release()

    def addConn(self, conn):
        try:
            self.threadsLock.acquire()
            if self.running:
                self.threads.append(conn)
        finally:
            self.threadsLock.release()

    def removeConn(self, conn):
        try:
            self.threadsLock.acquire()
            self.threads.remove(conn)
        finally:
            self.threadsLock.release()

    def close(self):
        try:
            self.running = False
            self.threadsLock.acquire()

            threads = list(self.threads)
            for c in threads:
                c.close()
        finally:
            self.threadsLock.release()


class ConnectionHandler(threading.Thread):
    def __init__(self, socClient, server, addr):
        threading.Thread.__init__(self)
        self.clientClosed = False
        self.targetClosed = True
        self.client = socClient
        self.client_buffer = ''
        self.server = server
        self.log = 'Connection: ' + str(addr)

    def close(self):
        try:
            if not self.clientClosed:
                self.client.shutdown(socket.SHUT_RDWR)
                self.client.close()
        except:
            pass
        finally:
            self.clientClosed = True

        try:
            if not self.targetClosed:
                self.target.shutdown(socket.SHUT_RDWR)
                self.target.close()
        except:
            pass
        finally:
            self.targetClosed = True

    def run(self):
        try:
            self.client_buffer = self.client.recv(BUFLEN)

            hostPort = self.findHeader(self.client_buffer, 'X-Real-Host')

            if hostPort == '':
                hostPort = DEFAULT_HOST

            split = self.findHeader(self.client_buffer, 'X-Split')

            if split != '':
                self.client.recv(BUFLEN)

            if hostPort != '':
                passwd = self.findHeader(self.client_buffer, 'X-Pass')
				
                if len(PASS) != 0 and passwd == PASS:
                    self.method_CONNECT(hostPort)
                elif len(PASS) != 0 and passwd != PASS:
                    self.client.send('HTTP/1.1 400 WrongPass!\r\n\r\n')
                elif hostPort.startswith('127.0.0.1') or hostPort.startswith('localhost'):
                    self.method_CONNECT(hostPort)
                else:
                    self.client.send('HTTP/1.1 403 Forbidden!\r\n\r\n')
            else:
                print '- No X-Real-Host!'
                self.client.send('HTTP/1.1 400 NoXRealHost!\r\n\r\n')

        except Exception as e:
            self.log += ' - error: ' + e.strerror
            self.server.printLog(self.log)
	    pass
        finally:
            self.close()
            self.server.removeConn(self)

    def findHeader(self, head, header):
        aux = head.find(header + ': ')

        if aux == -1:
            return ''

        aux = head.find(':', aux)
        head = head[aux+2:]
        aux = head.find('\r\n')

        if aux == -1:
            return ''

        return head[:aux];

    def connect_target(self, host):
        i = host.find(':')
        if i != -1:
            port = int(host[i+1:])
            host = host[:i]
        else:
            if self.method=='CONNECT':
                port = 443
            else:
                port = 80
                port = 8080
                port = 8799
                port = 3128

        (soc_family, soc_type, proto, _, address) = socket.getaddrinfo(host, port)[0]

        self.target = socket.socket(soc_family, soc_type, proto)
        self.targetClosed = False
        self.target.connect(address)

    def method_CONNECT(self, path):
        self.log += ' - CONNECT ' + path

        self.connect_target(path)
        self.client.sendall(RESPONSE)
        self.client_buffer = ''

        self.server.printLog(self.log)
        self.doCONNECT()

    def doCONNECT(self):
        socs = [self.client, self.target]
        count = 0
        error = False
        while True:
            count += 1
            (recv, _, err) = select.select(socs, [], socs, 3)
            if err:
                error = True
            if recv:
                for in_ in recv:
		    try:
                        data = in_.recv(BUFLEN)
                        if data:
			    if in_ is self.target:
				self.client.send(data)
                            else:
                                while data:
                                    byte = self.target.send(data)
                                    data = data[byte:]

                            count = 0
			else:
			    break
		    except:
                        error = True
                        break
            if count == TIMEOUT:
                error = True

            if error:
                break


def print_usage():
    print 'Usage: proxy.py -p <port>'
    print '       proxy.py -b <bindAddr> -p <port>'
    print '       proxy.py -b 0.0.0.0 -p 80'

def parse_args(argv):
    global LISTENING_ADDR
    global LISTENING_PORT

    try:
        opts, args = getopt.getopt(argv,"hb:p:",["bind=","port="])
    except getopt.GetoptError:
        print_usage()
        sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print_usage()
            sys.exit()
        elif opt in ("-b", "--bind"):
            LISTENING_ADDR = arg
        elif opt in ("-p", "--port"):
            LISTENING_PORT = int(arg)


def main(host=LISTENING_ADDR, port=LISTENING_PORT):

    print "\n:-------PythonProxy-------:\n"
    print "Listening addr: " + LISTENING_ADDR
    print "Listening port: " + str(LISTENING_PORT) + "\n"
    print ":-------------------------:\n"

    server = Server(LISTENING_ADDR, LISTENING_PORT)
    server.start()

    while True:
        try:
            time.sleep(2)
        except KeyboardInterrupt:
            print 'Stopping...'
            server.close()
            break

if __name__ == '__main__':
    parse_args(sys.argv[1:])
    main()
EOM
chmod +x /usr/local/sbin/socks2.py
screen -dmS socks python /usr/local/sbin/socks2.py

cat << XYZZY > /etc/systemd/system/rc-local.service
[Unit]
 Description=/etc/rc.local Compatibility
 ConditionPathExists=/etc/rc.local

[Service]
 Type=forking
 ExecStart=/bin/bash /etc/rc.local
 TimeoutSec=0
 StandardOutput=tty
 RemainAfterExit=yes
 SysVStartPriority=99

[Install]
 WantedBy=multi-user.target
XYZZY
chmod +x /etc/systemd/system/rc-local.service


cat << EOF >/etc/rc.local
#!/bin/sh -e
/sbin/sysctl -p
sysctl -p
screen -dmS socks python /usr/local/sbin/socks.py
screen -dmS socks python /usr/local/sbin/socks2.py
exit 0
EOF
chmod +x /etc/rc.local
systemctl enable rc-local
systemctl start rc-local.service

# install dropbear
apt-get -y install dropbear
sed -i 's/NO_START=1/NO_START=0/g' /etc/default/dropbear
sed -i 's/DROPBEAR_PORT=22/DROPBEAR_PORT=143/g' /etc/default/dropbear
sed -i 's/DROPBEAR_EXTRA_ARGS=/DROPBEAR_EXTRA_ARGS="-p 555"/g' /etc/default/dropbear
echo "/bin/false" >> /etc/shells
service ssh restart
service dropbear restart

#Installing Stunnel
apt-get -y install stunnel4
cat <<EOF >/etc/stunnel/stunnel.pem
-----BEGIN RSA PRIVATE KEY-----
MIIEpQIBAAKCAQEA+A7kkUwhEiVc3V2vQMCnkXxhU/U9eXVgcyMBLDjZ5tcYP41I
wfhrNH3kNIGLc/C1w9eM13hX7lxaZlInMb4ZWfDOy8/WLNC4XdT/74ucGqtlNDvu
bCL617hr0NyLkf9KRxQlaa/Mc7qu18sMyX+AUJsKLrigxXQC3XQ7S/i3YfGBU6x1
V9G+aXq2t3z/dAQK6mcUj/5YArEBc1YpdJpEkSXyMfWZByjE5QlBeHfe/eGnxOoV
3VLFObil/FdwsK/F4hAW4SWSLAf3KY8IjiicRgXk3Vcm5eQAftsluuNdMFNR+0wp
z1jHl7G6mTwTXyAuB1lvyRPO8iSyueAwRfAgTwIDAQABAoIBAQC14oWqHD4rhgXf
su/r9Ndpj9/1pd6bjntYMRSNDmqIHrOC9d+hirtg0+ZesZZFPvyoSwbUf0NKXaFT
YW2nxZHlJvMa8pxCZBCrjKDVTnL6Ay7D7CXYWJXBU1KK5QvZ02ztTVJZejPZr8rA
I/yOStUVRXlj5LDN11C6fJ12CTq9rtvtMS792ZNtCxGvQJuV5OQEhukp2ycjwU3P
RHErEC7Gkhdo7netjwOmBvysikPmtheE8IZOpx/yok+pRB1zrzWExAM7nZHNQsR4
jF1xJiaQ4/9a7PGNvbHOj8YarbWxGPHzrWYvrzz4P8ZwgWnv5gdOWsBJTG+sUNJ2
n5dCXlIBAoGBAPzWxrs7ACW8ZUwqvKyhTjAAmpMz6I/VQNbtM/TEKCUpMaXXCSar
ItnmSXwt29c0LSoHifwlBenUx+QB/o5qr2idbbJRbU1Pz4PcIRCdKcu0t4PoeJJM
T6CzXNs46Sg98HZ46WW0HesI8UNbwa8vj8B92O9Z5CoFOStYb4cRxFbPAoGBAPso
0Lx+ZCqA3+++BFaqsFjdh8YL3UOjm1oSn/ip1Stgv0Jl862RQA3aB5nNMutuPBIc
gAlb1M66J7v7STe5nKFPHELUprwHReXlrjSkyNxmP2LkCJFpGBm1AOc5meL0avXH
yzmqEdOvXKC06D0eZlBtLnfITwRgcjMoiHxF8f6BAoGAeuA+ULvJxI0chbm3XAZA
o1+Hv8ZYXZ58FnfM6kVyZSzx7fDlh59gHpmmWO1Ii/vVfzmOu7WafBtm0c6OUdRT
TvpDV4fvIMWKykBu6U4YA+Hd1gNipWbkw+qnU/sChQYlGM6GT2ELsS/1YJD1PhhV
Om1uwlPjaPCE6iXefbwKuU0CgYEA4274ZlhFuD9viZeWMizq9+3TT0HbIa77tLr8
5Z5VDKzVRPkxilDnoiN3kozAuXTfLL9mKhNgR7tG0/EfQjjwXxpWSyZpvgcQArjT
4ZP+16Y3bAN2xsZWLqE7qib89QnD+cDshNE+x2QbCuQHEaF/oQDdfVaER0BW6YCg
53gnRQECgYEA0CbUEO4JPIN6djkwX8a1GbEow85DMKvEchmwCdW8CvUunlULzZlS
ezC6w+/xCAP2jU6qOPR0aQV11oxnX4BimvZHCTuqDokHdS38KWcPjHy/A/XHU2dl
OpQXVN1JwM0kcBY8IaTS22CRm1wGTytVX72QwyayrqVsjd2N6yHQSxk=
-----END RSA PRIVATE KEY-----
-----BEGIN CERTIFICATE-----
MIID0TCCArmgAwIBAgIJALf1kKi2R1g3MA0GCSqGSIb3DQEBCwUAMH8xCzAJBgNV
BAYTAlBIMQswCQYDVQQIDAJRQzELMAkGA1UEBwwCUUMxDzANBgNVBAoMBkNRS1ZQ
TjEUMBIGA1UECwwLY3FrLXZwbi5jb20xEDAOBgNVBAMMB3hELWNSaXoxHTAbBgkq
hkiG9w0BCQEWDmNyaXpAZ21haWwuY29tMB4XDTE4MDcwMjE3MDMxOFoXDTIxMDcw
MTE3MDMxOFowfzELMAkGA1UEBhMCUEgxCzAJBgNVBAgMAlFDMQswCQYDVQQHDAJR
QzEPMA0GA1UECgwGQ1FLVlBOMRQwEgYDVQQLDAtjcWstdnBuLmNvbTEQMA4GA1UE
AwwHeEQtY1JpejEdMBsGCSqGSIb3DQEJARYOY3JpekBnbWFpbC5jb20wggEiMA0G
CSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQD4DuSRTCESJVzdXa9AwKeRfGFT9T15
dWBzIwEsONnm1xg/jUjB+Gs0feQ0gYtz8LXD14zXeFfuXFpmUicxvhlZ8M7Lz9Ys
0Lhd1P/vi5waq2U0O+5sIvrXuGvQ3IuR/0pHFCVpr8xzuq7XywzJf4BQmwouuKDF
dALddDtL+Ldh8YFTrHVX0b5pera3fP90BArqZxSP/lgCsQFzVil0mkSRJfIx9ZkH
KMTlCUF4d9794afE6hXdUsU5uKX8V3Cwr8XiEBbhJZIsB/cpjwiOKJxGBeTdVybl
5AB+2yW6410wU1H7TCnPWMeXsbqZPBNfIC4HWW/JE87yJLK54DBF8CBPAgMBAAGj
UDBOMB0GA1UdDgQWBBRuC0gqbi8q0u1gRWkD4M6JOXfDMDAfBgNVHSMEGDAWgBRu
C0gqbi8q0u1gRWkD4M6JOXfDMDAMBgNVHRMEBTADAQH/MA0GCSqGSIb3DQEBCwUA
A4IBAQBJ5uuyTBaCmXu5BDwvHWfn/BoRMLghdaoT5OkWNHlQ6XXriKOLvMrK1bnT
qU5JEiCF1vtJMjlG9okzFkgHdVzk7BgmwvFZXjCI1l8GhJiOMvqPweAiFYaV4Ny1
kIEocMeLLeX6MYTclHRQSeHWktE5tt0wPb25+jdd5Cf5Ikmzh1JLE2zKnZ8aRi5+
2p6D24FM7cYLkJUi5GJfWbMKy2kb5hgj89f9TSLa/SUUwxrktnIsntg7Mpj65SBc
qNRdgDhp7yhds2mQrFP+5yFpnE1Crw3YTBOr/4Oora6jYAG3gFDn6pwHK6SM1Iy0
xdnSR8pYhuw1OjnZhg6QV2lk68dM
-----END CERTIFICATE-----
EOF


cat <<EOF >/etc/stunnel/stunnel.conf
cert = /etc/stunnel/stunnel.pem
client = no
socket = a:SO_REUSEADDR=1
socket = l:TCP_NODELAY=1
socket = r:TCP_NODELAY=1
[sts]
connect = 127.0.0.1:143
accept = 443
[gtm]
connect = 127.0.0.1:555
accept = 4443
EOF

cd /etc/default && rm stunnel4
cat <<EOF >stunnel4
echo 'ENABLED=1
FILES="/etc/stunnel/*.conf"
OPTIONS=""
PPP_RESTART=0
RLIMITS=""'
EOF

chmod 755 stunnel4
update-rc.d stunnel4 defaults
systemctl enable stunnel4
systemctl restart stunnel4

cd
chmod 600 /etc/stunnel/stunnel.pem
echo "/sbin/nologin" >> /etc/shells
printf "\nAllowUsers root" >> /etc/ssh/sshd_config
echo "0 4 * * * root /sbin/reboot" > /etc/cron.d/reboot
useradd $USER
echo "$USER:$PASS" | chpasswd


clear
netstat -tunlp

sleep 3s
rm -rf *.sh &> /dev/null
cat /dev/null > ~/.bash_history && history -c && history -w
  echo "Server will secure this server and reboot after 20 seconds"
  sleep 20
  /sbin/reboot




