
import subprocess
import os.path
import unittest
import socket
import time

bin = os.environ.get('SIMPLE_BIN',
    os.path.join('.', 'build', 'test', 'simple'))
websockbin = os.environ.get('WEBSOCK_BIN',
    os.path.join('.', 'build', 'test', 'websocket'))

sample_output = (b'HTTP/1.1 200 OK\r\n'
    b'Content-Length:          130\r\n'
    b'Connection: close\r\n'
    b'\r\n'
    b'<!DOCTYPE html>\n'
    b'<html>\n'
    b'  <head><title>Hello from sample</title></head>\n'
    b'  <body>\n'
    b'    <h1>Hello from sample</h1>\n'
    b'  </body>\n'
    b'</html>\n\x00')

sample_output2 = (b'HTTP/1.1 200 OK\r\n'
    b'Content-Length:          130\r\n'
    b'Connection: Keep-Alive\r\n'
    b'\r\n'
    b'<!DOCTYPE html>\n'
    b'<html>\n'
    b'  <head><title>Hello from sample</title></head>\n'
    b'  <body>\n'
    b'    <h1>Hello from sample</h1>\n'
    b'  </body>\n'
    b'</html>\n\x00')

websock_request = (b'GET /echo HTTP/1.1\r\n'
    b'Host: localhost:8080\r\n'
    b'Connection: Upgrade\r\n'
    b'Sec-WebSocket-Key2: 12998 5 Y3 1  .P00\r\n'
    b'Upgrade: WebSocket\r\n'
    b'Sec-WebSocket-Key1: 4 @1  46546xW%0l 1 5\r\n'
    b'Origin: http://localhost\r\n'
    b'\r\n'
    b'^n:ds[4U')
websock_response = (b'HTTP/1.1 101 WebSocket Protocol Handshake\r\n'
    b'Upgrade: WebSocket\r\n'
    b'Connection: Upgrade\r\n'
    b'Sec-WebSocket-Location: ws://localhost:8080/echo\r\n'
    b'Sec-WebSocket-Origin: http://localhost\r\n'
    b'\r\n'
    b'8jKS\'y:G*Co,Wxa-')

class HTTP(unittest.TestCase):

    def setUp(self):
        self.proc = subprocess.Popen(bin)
        time.sleep(0.1)

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait()
        time.sleep(0.1)

    def testHTTP10(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output)

    def testHTTP11(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2)

    def testNoHost(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, b"") # host is required

    def testAlive(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: Keep-Alive\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2)
        sock.send(b"GET / HTTP/1.1\r\n"
            b"Connection: close\r\n"
            b"Host: localhost\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output)

    def testPipeline(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Connection: Keep-Alive\r\n\r\n"
            b"GET / HTTP/1.1\r\n"
            b"Connection: close\r\n"
            b"Host: localhost\r\n\r\n")
        time.sleep(0.1)
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2+sample_output)

    def testBody(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 128\r\n"
            b"Connection: close\r\n\r\n"
            + (b"1234"*32))
        time.sleep(0.1)
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output)

    def testBodyPipeline(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 32000\r\n"
            b"Connection: Keep-Alive\r\n\r\n"
            + (b"1234\n\n5678"*3200) +
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 1400\r\n"
            b"Connection: close\r\n\r\n"
            + (b"abcde\n\n"*200))
        time.sleep(0.1)
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2+sample_output)

    def testBodyPipeline1(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 320\r\n"
            b"Connection: Keep-Alive\r\n\r\n"
            + (b"1234\n\n5678"*32) +
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 1400\r\n"
            b"Connection: close\r\n\r\n"
            + (b"abcde\n\n"*200))
        time.sleep(0.1)
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2+sample_output)

    def testBodyPipeline2(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 32000\r\n"
            b"Connection: Keep-Alive\r\n\r\n"
            + (b"1234\n\n5678"*3200) + b"\r\n"
            b"POST / HTTP/1.1\r\n"
            b"Host: localhost\r\n"
            b"Content-Length: 1400\r\n"
            b"Connection: close\r\n\r\n"
            + (b"abcde\n\n"*200))
        time.sleep(0.1)
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2+sample_output)

class WebSocket(unittest.TestCase):

    def setUp(self):
        self.proc = subprocess.Popen(websockbin)
        time.sleep(0.1)

    def tearDown(self):
        self.proc.terminate()
        self.proc.wait()
        time.sleep(0.1)

    def testHandshake(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)

    def testEcho(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.send(b'\x00hello\xff')
        resp = sock.recv(4096)
        self.assertEquals(resp, b'\x00hello\xff')
        sock.send(b'\x00hello\xff\x00world\xff')
        time.sleep(0.1) # sorry, will fix that tomorrow :)
        resp = sock.recv(4096)
        self.assertEquals(resp, b'\x00hello\xff\x00world\xff')

    def testParts(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.send(b'\x00hell')
        time.sleep(0.01)
        sock.send(b'o\xff')
        resp = sock.recv(4096)
        self.assertEquals(resp, b'\x00hello\xff')
        sock.send(b'\x00hello\xff\x00wor')
        resp = sock.recv(4096)
        self.assertEquals(resp, b'\x00hello\xff')
        sock.send(b'ld\xff')
        resp = sock.recv(4096)
        self.assertEquals(resp, b'\x00world\xff')

if __name__ == '__main__':
    unittest.main()
