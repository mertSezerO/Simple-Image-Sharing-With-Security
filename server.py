import socket
import threading
import queue


class Server:

    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.image_cache = {}
        self.certificate_cache = {}

        self.create_connection_socket()
        self.create_image_sender_thread()
        self.create_notifier_thread()
        self.create_listener_thread()

    def create_connection_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(0)

    def create_image_sender_thread(self):
        self.send_queue = queue.Queue()
        self.sender = threading.Thread(target=self.send_image)

    def create_listener_thread(self):
        self.listener_thread = threading.Thread(target=self.listen_connection)

    def create_notifier_thread(self):
        self.notifier_thread = threading.Thread(target=self.notify_users)

    def send_image(self):
        pass

    def notify_users(self):
        pass

    def listen_connection(self):
        pass


# if main script
