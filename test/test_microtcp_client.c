/*
 * microtcp, a lightweight implementation of TCP for teaching,
 * and academic purposes.
 *
 * Copyright (C) 2015-2017  Manolis Surligas <surligas@gmail.com>
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

/*
 * You can use this file to write a test microTCP client.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h> 

int main(void){
    microtcp_sock_t client_socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (client_socket.state == INVALID) {
        fprintf(stderr, "Error creating client socket\n");
        return -1;
    }
    // Set up the server address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = inet_addr("127.0.0.1"); // Replace with the server's IP address
    server_address.sin_port = htons(8000); // Replace with the server's port number

    client_socket.servAdd = malloc(sizeof(struct sockaddr_in));
    memcpy(client_socket.servAdd, &server_address, sizeof(struct sockaddr_in));
    client_socket.serverAddrLen = malloc(sizeof(socklen_t));
    *client_socket.serverAddrLen = sizeof(struct sockaddr_in);
    // Connect to the server
    if (microtcp_connect(&client_socket, (struct sockaddr *)&server_address, sizeof(server_address)) == INVALID) {
    fprintf(stderr, "Error connecting to the server\n");
    return -1;
    }
    client_socket.servAdd = &server_address;
    socklen_t addr_len = sizeof(struct sockaddr_in);
    client_socket.serverAddrLen = &addr_len; 

    printf("Connected to the server.\n");

    // Perform any additional communication or data transfer here

    // Shutdown and close the socket
    microtcp_shutdown(&client_socket, 0); // 2 means both sending and receiving

    printf("Client shutting down.\n");

    return 0;
}
