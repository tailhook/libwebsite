
import subprocess
import os.path
import unittest
import socket
import time
import errno

from itertools import count

bin = os.environ.get('SIMPLE_BIN',
    os.path.join('.', 'build', 'test', 'simple'))
detbin = os.environ.get('DETAILED_BIN',
    os.path.join('.', 'build', 'test', 'detailed'))
websockbin = os.environ.get('WEBSOCK_BIN',
    os.path.join('.', 'build', 'test', 'websocket'))

sample_output = (b'HTTP/1.1 200 OK\r\n'
    b'Content-Length:          129\r\n'
    b'Connection: close\r\n'
    b'\r\n'
    b'<!DOCTYPE html>\n'
    b'<html>\n'
    b'  <head><title>Hello from sample</title></head>\n'
    b'  <body>\n'
    b'    <h1>Hello from sample</h1>\n'
    b'  </body>\n'
    b'</html>\n')

sample_output2 = (b'HTTP/1.1 200 OK\r\n'
    b'Content-Length:          129\r\n'
    b'Connection: Keep-Alive\r\n'
    b'\r\n'
    b'<!DOCTYPE html>\n'
    b'<html>\n'
    b'  <head><title>Hello from sample</title></head>\n'
    b'  <body>\n'
    b'    <h1>Hello from sample</h1>\n'
    b'  </body>\n'
    b'</html>\n')

detailed_output1 = (b'HTTP/1.1 200 OK\r\n'
    b'Content-Length:          129\r\n'
    b'Connection: close\r\n'
    b'X-Request-ID: 0\r\n'
    b'X-Connection-ID: 0\r\n'
    b'Content-Type: text/html\r\n'
    b'\r\n'
    b'<!DOCTYPE html>\n'
    b'<html>\n'
    b'  <head><title>Hello from sample</title></head>\n'
    b'  <body>\n'
    b'    <h1>Hello from sample</h1>\n'
    b'  </body>\n'
    b'</html>\n')
detailed_output2 = (b'HTTP/1.1 200 OK\r\n'
    b'Content-Length:          129\r\n'
    b'Connection: close\r\n'
    b'X-Request-ID: 0\r\n'
    b'X-Connection-ID: 1\r\n'
    b'Content-Type: text/html\r\n'
    b'\r\n'
    b'<!DOCTYPE html>\n'
    b'<html>\n'
    b'  <head><title>Hello from sample</title></head>\n'
    b'  <body>\n'
    b'    <h1>Hello from sample</h1>\n'
    b'  </body>\n'
    b'</html>\n')

websock_request = (b'GET /echo HTTP/1.1\r\n'
    b'Host: localhost:8080\r\n'
    b'Connection: Upgrade\r\n'
    b'Upgrade: WebSocket\r\n'
    b'Sec-WebSocket-Key: x3JJHMbDL1EzLkh9GBhXDw==\r\n'
    b'Sec-WebSocket-Version: 13\r\n'
    b'Origin: http://localhost\r\n'
    b'\r\n')
websock_response = (b'HTTP/1.1 101 WebSocket Protocol Handshake\r\n'
    b'Upgrade: WebSocket\r\n'
    b'Connection: Upgrade\r\n'
    b'Sec-WebSocket-Accept: HSmrc0sMlYUkAGmm5OPpG2HaGWk=\r\n'
    b'\r\n')
websock_hello = b'\x81\x85\x00\x00\x00\x00hello'
websock_hello_re = b'\x81\x05hello'
websock_bye = b'\x81\x83\x00\x00\x00\x00bye'
websock_bye_re = b'\x81\x03bye'
websock_world = b'\x81\x85\x01\x02\x03\x04vmqhe'
websock_world_re = b'\x81\x05world'
websock_ping = b'\x89\x84\x00\x00\x00\x00gnip'
websock_ping_re = b'\x8A\x04gnip'
websock_hello_p1 = b'\x01\x85\x00\x00\x00\x00hello'
websock_hello_p2 = b'\x80\x85\x01\x02\x03\x04vmqhe'
websock_hello_world = b'\x81\x0Ahelloworld'

class HTTP(unittest.TestCase):

    def setUp(self):
        self.proc = subprocess.Popen(bin)
        if 'DEBUG' in os.environ:
            print("No do:")
            print("gdb", bin, self.proc.pid)
            time.sleep(10)
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

    def testLongHeaders(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(5)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\n"
                  b"X-Test-Header: 1\r\n"
                  b"Host: localhost\r\n")
        time.sleep(0.2)
        sock.send(b"X-Test-Header2: 1\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2)

    def testLatency(self):
        tm = time.time()
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\nHost: localhost\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, sample_output2)
        self.assertLess(time.time() - tm, 0.1)

    def testNoHost(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.1\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, b"")  # host is required

    def testNotEndedHeader(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"DROPME / HTTP/1.1\r\nUpgrade: Something\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, b"")  # host is required
        self.testHTTP10()  # still not crashed

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
        if 'DEBUG' in os.environ:
            print("No do:")
            print("gdb", websockbin, self.proc.pid)
            time.sleep(10)
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
        sock.send(websock_hello)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_re)
        sock.sendall(websock_hello + websock_world)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_re + websock_world_re)

    def testPing(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.send(websock_ping)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_ping_re)
        sock.sendall(websock_hello + websock_ping + websock_world)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_re
            + websock_ping_re + websock_world_re)

    def testBadClose(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.setblocking(False)
        val = sock.send(websock_hello*1000000)
        self.assertTrue(val < 7*100000)
        val = sock.send((websock_hello*1000000)[val:])
        self.assertTrue(val < 7*100000)
        time.sleep(0.1)
        sock.close()
        self.testEcho()

    def testParts(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.send(websock_hello[:3])
        time.sleep(0.01)
        sock.send(websock_hello[3:])
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_re)
        sock.send(websock_hello + websock_world[:8])
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_re)
        sock.send(websock_world[8:])
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_world_re)

    def testFrames(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.send(websock_hello_p1)
        time.sleep(0.01)
        sock.send(websock_hello_p2)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_world)

    def testForceDisconnect(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(websock_request)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_response)
        sock.send(websock_hello)
        time.sleep(0.01)
        sock.send(websock_bye)
        time.sleep(0.01)
        sock.send(websock_hello)
        resp = sock.recv(4096)
        self.assertEquals(resp, websock_hello_re)
        resp = sock.recv(4096)  #ensure connection is closed
        self.assertEquals(resp, b'')
        self.testEcho()

class DetailedHttp(unittest.TestCase):

    def setUp(self):
        self.proc = subprocess.Popen(detbin)
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
        self.assertEquals(resp, detailed_output1)

    def testNotEndedHeader(self):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"DROPME / HTTP/1.1\r\nUpgrade: Something\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEqual(resp, b"")  # host is required
        # still not crashed
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect(('localhost', 8080))
        sock.send(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
        resp = sock.recv(4096)
        self.assertEquals(resp, detailed_output2)

if __name__ == '__main__':
    unittest.main()
