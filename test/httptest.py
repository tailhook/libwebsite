
import subprocess
import os.path
import unittest
import socket
import time

bin = os.path.join('.', 'build', 'default', 'simple')

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

if __name__ == '__main__':
    unittest.main()
