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
        self.create_request_handler_thread()
        self.create_decryption_thread()
        self.create_encryption_thread()

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

    def create_request_handler_thread(self):
        self.request_queue = queue.Queue()
        self.request_handler_thread = threading.Thread(target=self.handle_request)

    def create_encryption_thread(self):
        self.encrypt_queue = queue.Queue()
        self.encryption_thread = threading.Thread(target=self.encrypt_image)

    def create_decryption_thread(self):
        self.decrypt_queue = queue.Queue()
        self.decryption_thread = threading.Thread(target=self.decrypt_image)

    def create_store_thread(self):
        self.store_queue = queue.Queue()
        self.storer_thread = threading.Thread(target=self.store)

    def create_fetch_thread(self):
        self.fetch_queue = queue.Queue()
        self.fetcher_thread = threading.Thread(target=self.fetch)

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
                self.store_queue.put((client_socket, packet))
            elif packet.header == "DATA":
                self.decrypt_queue.put(packet)
            elif packet.header == "MESSAGE":
                self.fetch_queue.put((client_socket, packet))
            else:
                print("Error: Unknown packet header")


if __name__ == "__main__":
    server = Server()
    server.start()
