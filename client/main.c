#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>

#define SERVER_HOST "172.30.97.136"
#define SERVER_PORT 23456

char buffer[1024];

int main() {
    // Create a socket
    int client_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (client_socket == -1) {
        perror("Socket creation failed");
        exit(EXIT_FAILURE);
    }

    // Server address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_port = htons(SERVER_PORT);
    server_address.sin_addr.s_addr = inet_addr(SERVER_HOST);

    // Connect to the server
    if (connect(client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == -1) {
        perror("Connection failed");
        exit(EXIT_FAILURE);
    }

    while (1) {
        // Receive a message from the server
        recv(client_socket, buffer, sizeof(buffer), 0);
        printf("Message from server: %s\n", buffer);

        // Send a message to the server
        char message_to_server[] = "Hello from the client!";
        send(client_socket, message_to_server, strlen(message_to_server), 0);

        // sleep 1 second
        sleep(1);
    }

    // Close the socket
    close(client_socket);

    return 0;
}
