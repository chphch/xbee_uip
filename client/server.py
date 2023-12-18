import socket

# Create a socket object
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

# Bind the socket to a specific address and port
SERVER_HOST = '0.0.0.0'
SERVER_PORT = 23456

server_socket.bind((SERVER_HOST, SERVER_PORT))

# Listen for incoming connections
server_socket.listen()
print(f"Server listening on {SERVER_HOST}:{SERVER_PORT}")

# Accept a connection from a client
client_socket, client_address = server_socket.accept()
print(f"Connection from {client_address}")

while True:
    # Send a message to the client
    message_to_client = "Hello from the server!"
    client_socket.send(message_to_client.encode())

    # Receive data from the client
    data_from_client = client_socket.recv(1024).decode()
    print(f"Data from client: {data_from_client}")

# Close the connection
client_socket.close()
server_socket.close()
