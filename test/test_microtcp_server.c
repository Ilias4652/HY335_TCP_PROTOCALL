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
 * You can use this file to write a test microTCP server.
 * This file is already inserted at the build system.
 */

#include "../lib/microtcp.h"
#include <stdio.h>
#include <stdlib.h>
#include <arpa/inet.h>

int main(void)
{
    // Create a server socket
    microtcp_sock_t server_socket = microtcp_socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (server_socket.state == INVALID)
    {
        fprintf(stderr, "Error creating server socket\n");
        return -1;
    }

    // Set up the server address and port
    struct sockaddr_in server_address;
    server_address.sin_family = AF_INET;
    server_address.sin_addr.s_addr = INADDR_ANY;
    server_address.sin_port = htons(8000); // Use the desired port number

    // Bind the server socket to the address
    if (microtcp_bind(&server_socket, (struct sockaddr *)&server_address, sizeof(server_address)) < 0)
    {
        fprintf(stderr, "Error binding server socket\n");
        return -1;
    }

    printf("Server is waiting for connections.\n");

    // Accept incoming connections
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    // Accept incoming connections

    if (microtcp_accept(&server_socket, (struct sockaddr *)server_socket.servAdd, 0) == INVALID)
    {
        fprintf(stderr, "Error accepting connection\n");
        return -1;
    }

    printf("Connection accepted from %s:%d\n", inet_ntoa(client_address.sin_addr), ntohs(client_address.sin_port));

    // Perform any additional communication or data transfer here

    // Shutdown and close the sockets
    microtcp_shutdown(&server_socket, 1);

    printf("Server shutting down.\n");

    return 0;
}
