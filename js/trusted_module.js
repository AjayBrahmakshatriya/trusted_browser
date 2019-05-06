var absolutePath = function(href) {
    var link = document.createElement("a");
    link.href = href;
    return link.href;
}
class TrustedModule {
	constructor(image_url, remote_attestation_server) {
		this.onmessage = null;
		this.onready = null;
		this.message_handler = function(x) {
			return function(event) {
				if (x.onmessage != null)
					x.onmessage(event.data)
			}
		}(this);
		this.image_url = image_url;
	}
	open() {
		this.socket = new WebSocket("ws://localhost:8082");
		this.socket.onmessage = function(x) {
			return function(event) {
				if(event.data == "OK") {
					x.socket.onmessage = x.message_handler;
					if (x.onready != null)
						x.onready();
				}else{
					console.log(event);
				}
			}
		}(this);
		this.socket.onopen = function(x) {
			return function() {
				x.socket.send(absolutePath(x.image_url));
			}
		}(this);
	}
	
	send(message) {
		this.socket.send(message);
	}
	terminate() {
		this.socket.close();
	}
}
