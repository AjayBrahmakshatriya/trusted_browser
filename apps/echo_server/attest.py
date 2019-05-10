import attestation_server
import sys

def handler(conn):
	message = conn.recv()
	if message.strip() == "HELLO FROM SERVER":
		conn.send("HELLO FROM ATTESTER")
	else:
		conn.send("WHO ARE YOU")
	return

attestation_server.start_server(8083, sys.argv[1], sys.argv[2], handler)
