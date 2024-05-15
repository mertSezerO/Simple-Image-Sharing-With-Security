import socket
import threading
import queue


class Client:

    def __init__(self, host, port):
        self.host = host
        self.port = port

        self.create_connection_socket()
        self.create_logger_thread()
        self.create_listener_thread()
        self.create_cli_listener_thread()
        self.create_uploader_thread()
        self.create_downloader_thread()

    def create_connection_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(1)

    def create_logger_thread(self):
        self.log_queue = queue.Queue()
        self.logger_thread = threading.Thread(target=self.log)

    def create_listener_thread(self):
        self.listener_thread = threading.Thread(target=self.listen_server)

    def create_cli_listener_thread(self):
        self.cli_listener_thread = threading.Thread(target=self.listen_cli)

    def create_uploader_thread(self):
        self.uploader_thread = threading.Thread(target=self.upload_image)

    def create_downloader_thread(self):
        self.downloader_thread = threading.Thread(target=self.download_image)

    # Listener thread will be started in this method
    def connect(self):
        # Key generation
        # Verification
        # Listener start
        pass

    def log(self):
        pass

    def listen_server(self):
        pass

    def listen_cli(self):
        pass

    def upload_image(self):
        pass

    def download_image(self):
        pass

    def display_image(self):
        pass


# if main script
