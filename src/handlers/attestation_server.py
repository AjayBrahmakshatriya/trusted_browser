import sys
import os
import socket
import threading
import base64
import hashlib
import subprocess
import tempfile

ATTESTATION_BINARY_PATH="ATTESTATION_BINARY_PATH_PLACEHOLDER"


ATTESTATION_CODE_OK=  "0x0000000000000000"
ATTESTATION_CODE_FAIL="0x0000000000000001"



def recv_fixed_size(conn, size)
	data = ""
	while len(data) < size:
		data += conn.recv(size - len(data))
	return data


def recv_sized_message(conn):
	size = recv_fixed_size(conn, 18)
	size = int(size, 0)
	data = recv_fixed_size(conn, size)
	return data

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
	temp.write(key)
	temp.close()
	return temp.name


def attestation_handler(conn, socket, signing_key):
	report_file = read_report(conn)
	enclave_key = read_enclave_key(conn)
	first_message = read_first_message(conn)
	print report_file
	print enclave_key
	print first_message
	process = subprocess.Popen([ATTESTATION_BINARY_PATH, report_file, enclave_key, signing_key, first_message, attestation_key], stdout=subprocess.PIPE)
	(out, err) = process.communicate()
	out = out.strip()
	print out
	if out == "ATTESTATION SUCCEEDED":
		conn.send(ATTESTATION_CODE_OK)
	else:
		conn.send(ATTESTATION_CODE_FAIL)
		return
	os.unlink(report_file)
	os.unlink(enclave_key)
	os.unlink(first_message)


def start_server(port, signing_key):
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", port))
	s.listen(1)

	while 1:
		(conn, addr) = s.accept()
		threading.Thread(target = attestation_handler, args=(conn, s, signing_key)).start()

if __name__ == "__main__":
	start_server(8083, sys.argv[1]) 

	
