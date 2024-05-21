import socket
import threading
import queue

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend


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

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        self.public_key = self.private_key.public_key()

    # Listener thread will be started in this method
    def connect(self, username):
        # REGISTER <username>
        self.username = username
        self.generate_key_pair()
        # Verification
        # Sender start
        # Listener start
        pass

    def log(self):
        pass

    def listen_server(self):
        pass

    def listen_cli(self):
        print(
            """WELCOME TO IMAGE SHARING SYSTEM!
              Command Formats:
              - For establish connection: REGISTER <your_username>
              - For upload an image: POST_IMAGE <image_name> <image_path>
              - For download an image: DOWNLOAD <image_name>
              """
        )
        while True:
            command = input("\n").split(" ")
            if command[0] == "REGISTER":
                self.connect(command[1])
            elif command[0] == "POST":
                # Pass the arguments to queue
                pass
            elif command[0] == "DOWNLOAD":
                # Pass the arguments to queue
                pass

    def upload_image(self):
        pass

    def download_image(self):
        pass

    def display_image(self):
        pass


# if main script
