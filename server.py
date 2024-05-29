import socket
import threading
import queue
import select
import pickle

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend
from PIL import Image

from protocol import SISP
import log


class Server:

    def __init__(self, host="localhost", port=3001):
        self.host = host
        self.port = port

        self.image_cache = {}
        self.certificate_cache = {}

        self.create_connection_socket()
        self.create_sender_thread()
        self.create_notifier_thread()
        self.create_listener_thread()
        self.create_request_handler_thread()
        self.create_decryption_thread()
        self.create_encryption_thread()
        self.create_image_storer_thread()
        self.create_user_storer_thread()
        self.create_fetch_thread()
        self.create_logger_thread()

    def start(self):
        self.generate_key_pair()

        self.sender_thread.start()
        self.notifier_thread.start()
        self.listener_thread.start()
        self.fetch_thread.start()
        self.request_handler_thread.start()
        self.decryption_thread.start()
        self.encryption_thread.start()
        self.image_storer_thread.start()
        self.user_storer_thread.start()
        self.logger_thread.start()

        print("Server started on port: {}", self.port)

    def create_connection_socket(self):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(0)
        self.socket.setblocking(False)

    def create_sender_thread(self):
        self.send_queue = queue.Queue()
        self.sender_thread = threading.Thread(target=self.send)

    def create_listener_thread(self):
        self.listener_thread = threading.Thread(target=self.listen_connection)

    def create_notifier_thread(self):
        self.notifier_thread = threading.Thread(target=self.notify_users)

    def create_request_handler_thread(self):
        self.request_queue = queue.Queue()
        self.request_handler_thread = threading.Thread(target=self.handle_request)

    def create_encryption_thread(self):
        self.encrypt_queue = queue.Queue()
        self.encryption_thread = threading.Thread(target=self.encrypt_image)

    def create_decryption_thread(self):
        self.decrypt_queue = queue.Queue()
        self.decryption_thread = threading.Thread(target=self.decrypt_image)

    def create_user_storer_thread(self):
        self.user_store_queue = queue.Queue()
        self.user_storer_thread = threading.Thread(target=self.store_user)

    def create_image_storer_thread(self):
        self.image_store_queue = queue.Queue()
        self.image_storer_thread = threading.Thread(target=self.store_image)

    def create_fetch_thread(self):
        self.fetch_queue = queue.Queue()
        self.fetch_thread = threading.Thread(target=self.fetch)

    def create_logger_thread(self):
        self.log_queue = queue.Queue()
        self.logger_thread = threading.Thread(target=self.log)

    def generate_key_pair(self):
        self.private_key = rsa.generate_private_key(
            public_exponent=65537, key_size=2048, backend=default_backend()
        )

        self.public_key = self.private_key.public_key()

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
                    self.log_queue.put(
                        ("Connection attempt accepted, from: {}", (client_socket,))
                    )
                else:
                    try:
                        data = notified_socket.recv(4096)
                        if data:
                            self.request_queue.put((client_socket, data))
                        else:
                            sockets_list.remove(notified_socket)
                            notified_socket.close()
                    except Exception as e:
                        print(f"Error: {e}")
                        sockets_list.remove(notified_socket)
                        notified_socket.close()

    def handle_request(self):
        while True:
            client_socket, serialized_packet = self.request_queue.get()
            packet = SISP.deserialize(serialized_packet)
            if packet.header == "CONNECT":
                self.user_store_queue.put((client_socket, packet))
            elif packet.header == "DATA":
                self.decrypt_queue.put(packet)
            elif packet.header == "MESSAGE":
                self.fetch_queue.put((client_socket, packet))
            else:
                print("Error: Unknown packet header")

    def log(self):
        while True:
            log_elements = self.log_queue.get()
            log.log_info(log_elements[0], *(log_elements[1]))

    def send(self):
        while True:
            task, client_socket, data = self.send_queue.get()
            packet = task()

            packet.set_body(**data)
            client_socket.sendall(SISP.serialize(packet))
            self.log_queue.put(
                ("New packet send, packet: {}, to: {}", (packet, client_socket))
            )

    def notify_users(self):
        pass

    def store_user(self):
        while True:
            client_socket, packet = self.user_store_queue.get()
            self.certificate_cache[packet.body.payload["Username"]] = (
                packet.body.payload["Public Key"]
            )

            self.log_queue.put(
                (
                    "New certificate saved, with username: {}, public key: {}",
                    (
                        packet.body.payload["Username"],
                        packet.body.payload["Public Key"],
                    ),
                )
            )

            response_payload = {
                "Username": packet.body.payload["Username"],
                "User Public Key": packet.body.payload["Public Key"],
            }

            certificate = pickle.dumps(response_payload)

            signature = self.private_key.sign(
                certificate,
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH,
                ),
                hashes.SHA256(),
            )

            serialized_pk = self.public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo,
            ).decode("utf-8")

            self.send_queue.put(
                (
                    SISP.create_message_packet,
                    client_socket,
                    {
                        "payload": {
                            "Signature": signature,
                            "Public Key": serialized_pk,
                        }
                    },
                )
            )

    def store_image(self):
        pass

    def fetch(self):
        pass

    def encrypt_image(self):
        pass

    def decrypt_image(self):
        pass


if __name__ == "__main__":
    server = Server()
    server.start()
