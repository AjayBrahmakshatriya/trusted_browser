import sys
import os
import socket
import threading
import base64
import hashlib
import subprocess
import tempfile
from Crypto.Cipher import AES
import random

ATTESTATION_BINARY_PATH="ATTESTATION_BINARY_PATH_PLACEHOLDER"


ATTESTATION_CODE_OK=  "0x0000000000000000"
ATTESTATION_CODE_FAIL="0x0000000000000001"



def recv_fixed_size(conn, size):
	data = ""
	while len(data) < size:
		chunk = conn.recv(size - len(data))
		if len(chunk) == 0:
			return ""
		data += chunk
	return data


def recv_sized_message(conn):
	size = recv_fixed_size(conn, 18)
	if size == "":
		return ""
	size = int(size, 0)
	data = recv_fixed_size(conn, size)
	return data


def send_sized_message(conn, message):
	size = len(message)
	conn.send('0x%016x' % size)
	conn.send(message) 

def read_report(conn):
	report = recv_sized_message(conn)
	temp = tempfile.NamedTemporaryFile(mode="w+b", delete=False)
	temp.write(report)
	temp.close()
	return temp.name
		
def read_enclave_key(conn):
	key = recv_sized_message(conn)
	temp = tempfile.NamedTemporaryFile(mode="w+b", delete=False)
	temp.write(key)
	temp.close()
	return temp.name

def read_first_message(conn):
	message = recv_sized_message(conn)
	temp = tempfile.NamedTemporaryFile(mode="w+b", delete=False)
	temp.write(message)
	temp.close()
	return temp.name


def aes_decrypt(e_message, key):
	IV = e_message[:16]
	e_message = e_message[16:]
	aes = AES.new(key, AES.MODE_CBC, IV)
	
	d_message = aes.decrypt(e_message)
	padding = ord(d_message[-1])
	d_message = d_message[:-padding]
	return d_message

def aes_encrypt(d_message, key):
	size = len(d_message)
	size = (size/16)*16 + 16
	padding = size - len(d_message)
	d_message += chr(padding)*padding
	IV = ''.join([chr(random.randint(0, 0xFF)) for i in range(16)])
	aes = AES.new(key, AES.MODE_CBC, IV)
	e_message = aes.encrypt(d_message)
	e_message = IV + e_message
	return e_message

class SecureConnection(object):
	def __init__(self, conn, key):
		self.conn = conn
		self.key = key
	def send(self, message):
		send_sized_message(self.conn, aes_encrypt(message, self.key))
	def recv(self):
		message = recv_sized_message(self.conn)
		if len(message) == 0:
			return ""
		message = aes_decrypt(message, self.key)
		return message
	
def attestation_handler(conn, socket, signing_key, attestation_key, handler):
	report_file = read_report(conn)
	enclave_key = read_enclave_key(conn)
	first_message = read_first_message(conn)
	print report_file
	print enclave_key
	print first_message
	process = subprocess.Popen([ATTESTATION_BINARY_PATH, report_file, enclave_key, signing_key, first_message, attestation_key], stdout=subprocess.PIPE)
	(out, err) = process.communicate()
	out = out.strip().split("\n")
	status = out[0].strip()
	if status == "ATTESTATION SUCCEEDED":
		conn.send(ATTESTATION_CODE_OK)
	else:
		conn.send(ATTESTATION_CODE_FAIL)
		return
	symmetric_key = out[1].strip()
	symmetric_key = symmetric_key.decode("hex")
		
	#os.unlink(report_file)
	#os.unlink(enclave_key)
	#os.unlink(first_message)
	secconn = SecureConnection(conn, symmetric_key)
	handler(secconn)

def start_server(port, signing_key, attestation_key, handler):
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", port))
	s.listen(1)

	while 1:
		(conn, addr) = s.accept()
		threading.Thread(target = attestation_handler, args=(conn, s, signing_key, attestation_key, handler)).start()

def NULL_HANDLER(conn):
	pass
if __name__ == "__main__":
	start_server(8083, sys.argv[1], sys.argv[2], NULL_HANDLER)

	
