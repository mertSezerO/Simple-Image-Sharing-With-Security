# Simple-Image-Sharing-With-Security
Simple Image Sharing System
Group Members
Member 1: Ece Kızılkaya, 150119065
Member 2: Gamze Ndiye Şahin, 150119043
Member 3: Mert Sezer Oktay , 150120017

Introduction
The Image Sharing System is a client-server application designed for securely sharing images between multiple users over a network. The system utilizes asymmetric and symmetric encryption to ensure secure communication and image transfer. It also includes logging mechanisms for tracking system events.

Components
1. Client
The client component allows users to register, upload, download, and display images. It establishes a secure connection with the server, handles user commands, and manages encryption and decryption of images.

2. Server
The server component manages client connections, handles image storage and retrieval, and ensures secure communication between clients and the server. It uses encryption to protect image data and public key certificates to verify user identities.

3. Protocol
The protocol component defines the structure of packets used for communication between the client and server. It includes methods for creating, serializing, and deserializing packets.

Features
Client Features
Connection Establishment:
The client connects to the server using a specified username.
Generates a public-private key pair for secure communication.
Sends a connection packet to the server with the public key.,

Image Upload:
Encrypts images using AES encryption.
Signs the encrypted image with the user's private key.
Uploads the encrypted image to the server.

Image Download:
Requests an image from the server.
Decrypts the received image using the private key.

Image Display:
Displays downloaded images using the PIL library.

Server Features
User Management:
Manages user connections and stores public keys.
Verifies user certificates.

Image Management:
Stores and manages uploaded images.
Encrypts and decrypts images for secure transmission.

Communication:
Handles client requests and responses.
Notifies clients of new image uploads.

Logging:
Logs system events and user activities.

Usage

Client Usage
Run the Client: python client.py <port>

Register: REGISTER <username>
Upload an image: POST_IMAGE <image_name> <image_path>
Download an image: DOWNLOAD <image_name>
Display an image: DISPLAY <image_name>

Server Usage
Run the Server: python server.py


Implementation Details
Client Implementation

Connection Handling:
Establishes a connection with the server.
Sends the public key to the server for secure communication.
Listens for server responses and handles them accordingly.

Image Encryption and Decryption:
Uses AES encryption for image data.
Encrypts AES keys with the server's public key.
Signs images with the client's private key.
Verifies image signatures upon download.

Thread Management:
Multiple threads handle logging, listening for commands, sending data, and encrypting/decrypting images.

Server Implementation
Connection Handling:
Listens for incoming client connections.
Manages connected client sockets.
Handles client requests and responses.

Image Storage:
Stores encrypted images and associated metadata.
Retrieves and encrypts images for secure transmission to clients.

Key Management:
Generates and manages the server's key pair.
Stores and verifies client public keys.

Thread Management:
Multiple threads handle logging, listening for connections, processing requests, and encrypting/decrypting images.

Protocol Implementation
Packet Structure:
Defines SISPPacket class for creating different types of packets.
Supports connection, data, and message packets.

Serialization:
Uses pickle for serializing and deserializing packet data.

Conclusion
The Image Sharing System provides a secure and efficient way to share images over a network. It ensures data security through encryption and authentication mechanisms, making it a robust solution for secure image sharing.