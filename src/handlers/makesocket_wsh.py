_REQUEST_MESSAGE = u'open_socket'

def web_socket_do_extra_handshake(request):
    # This example handler accepts any request. See origin_check_wsh.py for how
    # to reject access from untrusted scripts based on origin value.

    pass  # Always accept.

def web_socket_transfer_data(request):
    while True:
        line = request.ws_stream.receive_message()
        if line is None:
            return
        if line == _REQUEST_MESSAGE:
            # START THE ENCLAVE AND FORWARD THE SOCKET
            request.ws_stream.send_message("opened", binary=False)
        else:
            request.ws_stream.send_message(line, binary=False)
            
        