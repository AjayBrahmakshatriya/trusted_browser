import socket
import os
import threading
import hashlib
import base64

BINARY_PATH="BINARY_PATH_PLACEHOLDER"

def read_headers(conn):
	headers = ""
	while headers[-4:] != '\r\n\r\n':
		read = conn.recv(1024)
		headers+= read
	return headers

def parse_headers(headers):
	header_dict = {}
	headers = headers[:-4]
	headers = headers.split("\r\n")
	headers = headers[1:]
	for i in headers:
		split = i.split(":", 1)
		key = split[0].strip()
		value = split[1].strip()	
		header_dict[key] = value
	return header_dict


def websocket_handler(conn, socket):
        headers = read_headers(conn)
        headers = parse_headers(headers)
        if "Sec-WebSocket-Key" not in headers:
                conn.close()
                return
        header_key = headers["Sec-WebSocket-Key"]
        response_string = header_key + "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
        response_string = hashlib.sha1(response_string).digest()
        response_string = base64.b64encode(response_string)

        response = "HTTP/1.1 101 Switching Protocols\r\n" \
                 + "Upgrade: websocket\r\n" \
                 + "Connection: Upgrade\r\n" \
                 + "Sec-WebSocket-Accept: " + response_string + "\r\n" \
                 + "\r\n"
        conn.send(response)
	print ("Starting enclave")       
        if os.fork():
            conn.close()
            return
        else:
            socket.close()
            os.execv(BINARY_PATH, [BINARY_PATH, str(conn.fileno())])
            exit(-2)


def start_server(port):
	s = socket.socket()
	s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
	s.bind(("0.0.0.0", port))
	s.listen(1)

	while 1:
		(conn, addr) = s.accept()
		threading.Thread(target=websocket_handler, args=(conn, s)).start()


if __name__ == "__main__":
    start_server(8082)	
