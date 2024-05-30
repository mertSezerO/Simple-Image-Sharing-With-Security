import socket
import threading
import queue
import select
import pickle

from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.backends import default_backend

from protocol import SISP
import log


class Server:

    def __init__(self, host="localhost", port=8000):
        self.host = host
        self.port = port

        self.image_cache = {}
        self.certificate_cache = {}

        self.create_connection_socket()
        self.socket_list = [self.socket]

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

        print("Server started on port: {}".format(self.port))

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
        self.notify_queue = queue.Queue()
        self.notifier_thread = threading.Thread(target=self.notify_users)

    def create_request_handler_thread(self):
        self.request_queue = queue.Queue()
        self.request_handler_thread = threading.Thread(target=self.handle_request)

    def create_encryption_thread(self):
        self.encrypt_queue = queue.Queue()
        self.encryption_thread = threading.Thread(target=self.encrypt_keys)

    def create_decryption_thread(self):
        self.decrypt_queue = queue.Queue()
        self.decryption_thread = threading.Thread(target=self.decrypt_keys)

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
        while True:
            read_sockets, _, exception_sockets = select.select(
                self.socket_list, [], self.socket_list
            )
            for notified_socket in read_sockets:
                if notified_socket == self.socket:
                    client_socket, _ = self.socket.accept()
                    self.socket_list.append(client_socket)
                    self.log_queue.put(
                        ("Connection attempt accepted, from: {}", (client_socket,))
                    )
                else:
                    try:
                        data = notified_socket.recv(4 * 1024 * 1024)
                        if data:
                            self.request_queue.put((client_socket, data))
                        else:
                            self.socket_list.remove(notified_socket)
                            notified_socket.close()
                    except Exception as e:
                        print(f"Error: {e}")
                        self.socket_list.remove(notified_socket)
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
        while True:
            image_name, image_data = self.image_store_queue.get()
            self.image_cache[image_name] = image_data
            self.log_queue.put(
                (
                    "New Image Posted, with name: {}, owner: {}",
                    (image_name, image_data["Owner"]),
                )
            )

            self.notify_queue.put((image_name, image_data["Owner"]))

    def notify_users(self):
        while True:
            image_name, image_owner = self.notify_queue.get()

            for socket in self.socket_list:
                if socket != self.socket:
                    packet = SISP.create_message_packet()
                    packet.set_body(
                        payload={"Image Name": image_name, "Owner": image_owner}
                    )
                    socket.sendall(SISP.serialize(packet))
                    self.log_queue.put(("Notified socket: {}", (socket,)))

    def fetch(self):
        while True:
            client_socket, received_pkt = self.fetch_queue.get()

            image_data = self.image_cache[received_pkt.body.payload["Name"]]
            self.log_queue.put(
                (
                    "Image Download Request, For Image: {}",
                    (received_pkt.body.payload["Name"],),
                )
            )

            self.encrypt_queue.put(
                (
                    client_socket,
                    received_pkt.body.payload["Name"],
                    image_data,
                    received_pkt.body.payload["Username"],
                )
            )

    def encrypt_keys(self):
        while True:
            client_socket, image_name, image_data, requesting_user = (
                self.encrypt_queue.get()
            )

            requesting_user_pk_str = self.certificate_cache[requesting_user]
            requesting_user_pk = serialization.load_pem_public_key(
                requesting_user_pk_str.encode()
            )

            encrypted_aes = requesting_user_pk.encrypt(
                image_data["AES Key"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            encrypted_iv = requesting_user_pk.encrypt(
                image_data["Init Vector"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            owner_pk = self.certificate_cache[image_data["Owner"]]

            self.send_queue.put(
                (
                    SISP.create_data_packet,
                    client_socket,
                    {
                        "payload": {
                            "Image": image_data["Image"],
                            "Name": image_name,
                        },
                        "auth": {
                            "Signature": image_data["Signature"],
                            "AES Key": encrypted_aes,
                            "Init Vector": encrypted_iv,
                            "Owner Public Key": owner_pk,
                        },
                    },
                )
            )

    def decrypt_keys(self):
        while True:
            image_pkt = self.decrypt_queue.get()

            aes_key = self.private_key.decrypt(
                image_pkt.body.auth["AES Key"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            iv = self.private_key.decrypt(
                image_pkt.body.auth["Init Vector"],
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None,
                ),
            )

            self.image_store_queue.put(
                (
                    image_pkt.body.payload["Name"],
                    {
                        "Image": image_pkt.body.payload["Image"],
                        "Owner": image_pkt.body.payload["Owner"],
                        "Signature": image_pkt.body.auth["Signature"],
                        "AES Key": aes_key,
                        "Init Vector": iv,
                    },
                )
            )


if __name__ == "__main__":
    server = Server()
    server.start()
