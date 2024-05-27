import os
import socket
import threading
import queue
import hashlib
import base64

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, padding
from cryptography.hazmat.primitives.asymmetric import padding as asym_padding
from cryptography.hazmat.backends import default_backend
from protocol import SISP
from PIL import Image


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
        self.create_sender_thread()

    def start(self):
        self.logger_thread.start()
        self.cli_listener_thread.start()
        self.uploader_thread.start()
        self.downloader_thread.start()

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

    def create_sender_thread(self):
        self.sender_queue = queue.Queue()
        self.sender_thread = threading.Thread(target=self.send)

    def create_uploader_thread(self):
        self.upload_queue = queue.Queue()
        self.uploader_thread = threading.Thread(target=self.upload_image)

    def create_downloader_thread(self):
        self.download_queue = queue.Queue()
        self.downloader_thread = threading.Thread(target=self.download_image)

    def create_encryption_thread(self):
        self.encrypt_queue = queue.Queue()
        self.encryption_thread = threading.Thread(target=self.encrypt_image)

    def create_decryption_thread(self):
        self.decrypt_queue = queue.Queue()
        self.decryption_thread = threading.Thread(target=self.decrypt_image)

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        self.public_key = self.private_key.public_key()

    def connect(self, username):
        self.username = username
        self.generate_key_pair()

        self.socket.connect(("localhost", 8080))
        connection_pkt = SISP.create_connection_packet()
        connection_pkt.set_body(username=self.username, public_key=self.public_key)
        self.socket.send(SISP.serialize(connection_pkt))

        while True:
            received_pkt = self.socket.recv(4096)
            if received_pkt is not None:
                deserialized_pkt = SISP.deserialize(received_pkt)
                try:
                    deserialized_pkt.body.public_key.verify(
                        deserialized_pkt.body.signature,
                        {"username": self.username, "public key": self.public_key},
                        padding.PSS(
                            mgf=padding.MGF1(hashes.SHA256()),
                            salt_length=padding.PSS.MAX_LENGTH,
                        ),
                        hashes.SHA256(),
                    )
                    self.public_key_server = deserialized_pkt.body.public_key
                except Exception as e:
                    self.log_queue.put("Signature is invalid!")
                break

        self.sender_thread.start()
        self.listener_thread.start()

    def log(self):
        while True:
            message = self.log_queue.get()
            print(message)

    def send(self):
        while True:
            try:
                packet = self.sender_queue.get()
                self.socket.send(packet.serialize())
            except Exception as e:
                print(f"Error sending packet to the server: {e}")
                break
        
    def listen_server(self):
        while True:
            try:
                message = self.socket.recv(1024).decode()
                if message:
                    self.handle_server_message(message)
            except Exception as e:
                print(f"Error listening to server: {e}")
                break

    def handle_server_message(self, message):
        parts = message.split(" ")
        command = parts[0]

        if command == "NEW_IMAGE":
            image_name = parts[1]
            owner_name = parts[2]
            print(f"New image posted: {image_name} by {owner_name}")
        else:
            print(f"Unknown command from server: {message}")

    def listen_cli(self):
        print(
            """WELCOME TO IMAGE SHARING SYSTEM!
              Command Formats:
              
        For establish connection: REGISTER <your_username>
        For upload an image: POST_IMAGE <image_name> <image_path>
        For download an image: DOWNLOAD <image_name>"""
        )
        while True:
            command = input("\n").split(" ")
            if command[0] == "REGISTER":
                self.connect(command[1])
            elif command[0] == "POST_IMAGE":
                image_name = command[1]
                image_path = command[2]
                self.encrypt_queue.put(
                    {
                        "Image Name": image_name,
                        "Image Path": image_path,
                    },
                )
            elif command[0] == "DOWNLOAD":
                image_name = command[1]
                self.request_image(image_name)
            else:
                self.log_queue.put(
                    """UNKNOWN COMMAND! PLEASE NOTE THAT:
              Command Formats:
              
        For establish connection: REGISTER <your_username>
        For upload an image: POST_IMAGE <image_name> <image_path>
        For download an image: DOWNLOAD <image_name>"""
                )

    def request_image(self, image_name):
        pass

    def upload_image(self):
        while True:
            task, data = self.upload_queue.get()
            image_pkt = task()
            image_pkt.set_body(
                payload={
                    "Image": data["Encrypted Image"],
                    "Name": data["Encrypted Image Name"],
                },
                auth={
                    "Signature": data["Signature"],
                    "AES Key": data["Encrypted AES Key"],
                    "Init Vector": data["Encrypted IV"],
                },
            )
            self.sender_queue.put(image_pkt)

    def download_image(self):
        while True:
            image_name = self.download_queue.get()[image_name]
            image_data = self.decrypt_queue.get()[image_data]

            with open(f"downloaded_{image_name}", "wb") as image_file:
                image_file.write(image_data)

    def display_image(self, image_name):
        try:
            image = Image.open(image_name)
            image.show()
        except Exception as e:
            print(f"Error displaying image: {e}")

    def encrypt_image(self):
        aes_key = os.urandom(32)
        iv = os.urandom(16)

        image = self.encrypt_queue.get()

        cipher = Cipher(
            algorithms.AES(aes_key), modes.CBC(iv), backend=default_backend()
        )

        with open(image["Image Path"], "r") as f:
            image_data = f.read()

        encryptor = cipher.encryptor()
        padded_image_data = self.pad(image_data)
        encrypted_image = encryptor.update(padded_image_data) + encryptor.finalize()

        encrypted_aes_key = self.server_public_key.encrypt(
            aes_key,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        encrypted_iv = self.server_public_key.encrypt(
            iv,
            asym_padding.OAEP(
                mgf=asym_padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None,
            ),
        )

        image_hash = hashlib.sha256(image_data).digest()

        signature = self.private_key.sign(
            image_hash,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256(),
        )

        self.upload_queue.put(
            SISP.create_data_packet,
            {
                "Encrypted Image": encrypted_image,
                "Image Name": image["Image Name"],
                "Encrypted AES Key": encrypted_aes_key,
                "Encrypted IV": encrypted_iv,
                "Signature": signature,
            },
        )

    def decrypt_image(self):
        pass

    def pad(self, data):
        pad_length = 16 - (len(data) % 16)
        return data + bytes([pad_length] * pad_length)


if __name__ == "__main__":
    client = Client()
    client.start()
