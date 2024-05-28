import socket
import threading
import queue
import select

from protocol import SISP


class Server:

    def __init__(self, host="localhost", port=3001):
        self.host = host
        self.port = port

        self.image_cache = {}
        self.certificate_cache = {}

        self.create_connection_socket()
        self.create_image_sender_thread()
        self.create_notifier_thread()
        self.create_listener_thread()

    def start(self):
        self.sender_thread.start()
        self.notifier_thread.start()
        self.listener_thread.start()

    def create_connection_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(0)
        self.socket.setblocking(False)

    def create_image_sender_thread(self):
        self.send_queue = queue.Queue()
        self.sender_thread = threading.Thread(target=self.send_image)

    def create_listener_thread(self):
        self.listener_thread = threading.Thread(target=self.listen_connection)

    def create_notifier_thread(self):
        self.notifier_thread = threading.Thread(target=self.notify_users)

    def send_image(self):
        pass

    def notify_users(self):
        pass

    # send CA encrypted, hash and server's public key directly
    def listen_connection(self):
        sockets_list = [self.socket]
        while True:
            read_sockets, _, exception_sockets = select.select(
                sockets_list, [], sockets_list
            )
            for notified_socket in read_sockets:
                if notified_socket == self.socket:
                    client_socket, _ = self.socket.accept()
                    sockets_list.append(client_socket)
                else:
                    try:
                        data = notified_socket.recv(4096)
                        if data:
                            packet = SISP.deserialize(data)
                            self.handle_request(notified_socket, packet)
                        else:
                            sockets_list.remove(notified_socket)
                            notified_socket.close()
                    except Exception as e:
                        print(f"Error: {e}")
                        sockets_list.remove(notified_socket)
                        notified_socket.close()

    def handle_request(self, socket, packet):
        print(socket, packet)


if __name__ == "__main__":
    server = Server()
    server.start()
