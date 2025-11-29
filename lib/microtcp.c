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

#include "microtcp.h"
#include "../utils/crc32.h"

microtcp_sock_t microtcp_socket(int domain, int type, int protocol) // initiates the socket
{                                                                   // creates socket based on udp and initializes its fields
  int sock;
  if ((sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP)) == -1)
  {
    perror("COULD NOT OPEN SOCKET ");
    microtcp_sock_t *socket = malloc(sizeof(microtcp_sock_t));
    memset(socket, 0, sizeof(microtcp_sock_t));
    socket->state = INVALID;
    return *socket;
  }
  microtcp_sock_t *socket = malloc(sizeof(microtcp_sock_t));
  socket->sd = sock; // setting the socket descriptor for our socket
  socket->init_win_size = MICROTCP_WIN_SIZE;
  socket->curr_win_size = socket->init_win_size;
  socket->cwnd = MICROTCP_INIT_CWND;
  socket->ssthresh = MICROTCP_INIT_SSTHRESH;
  // socket->recvbuf = MICROTCP_RECVBUF_LEN;
  socket->state = CREATED;
  return *socket;
}

int microtcp_bind(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) // bind the socket to a specific address and port. The bind function is used for this purpose
{                                                                                                 // binds socket to adresses
  int temp = bind(socket->sd, address, address_len);                                              // binds the socket to our ip address
  if (temp < 0)
  {
    perror("Couldnt bind");
    socket->state = INVALID;
    return -1;
  }
  return temp;
}

int microtcp_connect(microtcp_sock_t *socket, const struct sockaddr *address, socklen_t address_len) // is called by the client to connect to the server's ip
{
  /* connect function used from client to connect to server*/
  int recvtemp;
  microtcp_header_t msgClient;
  microtcp_header_t *msgServer = malloc(sizeof(microtcp_header_t)); // preparing necessary variab;es
  socket->state = CREATED;
  uint8_t buff[MICROTCP_RECVBUF_LEN];
  msgClient.seq_number = htonl(rand() % 100 + 1); // initial seq number
  msgClient.ack_number = 0;
  msgClient.control = htons(SYN); // first packet of handshake is syn
  msgClient.checksum = 0;
  msgClient.window = 0;
  for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  { // emptying buffer
    buff[i] = 0;
  }
  memcpy(buff, &msgClient, sizeof(microtcp_header_t));
  uint32_t csum = crc32(buff, sizeof(buff));
  msgClient.checksum = htonl(csum);                                                                                      // adding checksum for error checking
  if (sendto(socket->sd, (void *)&msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)address, address_len) < 0) // sending first packet of handshake
  {
    perror("Couldnt transmit first packet\n");
    socket->state = INVALID;
    return -1;
  }
  if (recvfrom(socket->sd, msgServer, sizeof(microtcp_header_t), 0, NULL, NULL) < 0) // sent first packet to server and waiting for a response
  {
    perror("Couldnt get response");
    socket->state = INVALID;
    return -1;
  } // recieving second packet of tcp connection from server
  csum = ntohl(msgServer->checksum);
  microtcp_header_t temp;
  temp.seq_number = msgServer->seq_number; // saving data of 2nd packet of handshake from server to save the data and check for correct transmission using checksum
  temp.ack_number = msgServer->ack_number;
  temp.control = msgServer->control;
  temp.window = msgServer->window;
  for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    buff[i] = 0;
  }
  memcpy(buff, &temp, sizeof(microtcp_header_t));
  uint32_t csum2 = crc32(buff, sizeof(buff));
  if (csum != csum2)
  { // making sure that packet was transferredd correctly using checksum
    perror("Error during transmission ,Checksum isn't the same\n");
    socket->state = INVALID;
    return -1;
  }
  msgServer->control = ntohs(msgServer->control);
  if (msgServer->control != SYN_ACK)
  { // making sure the packet we recieved is syn ack , since its 2nd packet
    socket->state = INVALID;
    return -1;
  }
  socket->curr_win_size = ntohs(msgServer->window);
  // creating 3rd packet of handshake
  memset(&msgClient, 0, sizeof(microtcp_header_t));
  msgServer->ack_number = ntohl(msgServer->ack_number);
  msgServer->seq_number = ntohl(msgServer->seq_number);
  msgClient.seq_number = htonl(msgServer->ack_number);
  msgClient.ack_number = htonl(msgServer->seq_number + 1);
  msgClient.control = htons(ACK); // last packet of handshake is ack before establishment of connection
  msgClient.window = htons(socket->curr_win_size);
  msgClient.checksum = 0;
  for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++)
  {
    buff[i] = 0;
  }
  memcpy(buff, &msgClient, sizeof(microtcp_header_t));
  csum = crc32(buff, sizeof(buff));
  msgClient.checksum = htonl(csum); // sending last packet to server
  if (sendto(socket->sd, (void *)&msgClient, sizeof(microtcp_header_t), 0, address, address_len) < 0)
  {
    perror("Error sending last packet of handshake\n");
    socket->state = INVALID;
    return -1;
  }
  socket->state = ESTABLISHED;
  socket->seq_number = ntohl(msgClient.seq_number); // nothing wrong connection established created ack and seq
  // for our socket
  socket->ack_number = ntohl(msgClient.ack_number);
  free(msgServer);
  printf("CONNECT DONE \n");
  return -1;
}

int microtcp_accept(microtcp_sock_t *socket, struct sockaddr *address, socklen_t address_len)
{
  /* function used by server to establish handshake, accepts the client connection */
  struct sockaddr_in client_address;
  socklen_t client_address_len = sizeof(client_address);
  int recvtemp;
  microtcp_header_t *msgClient = malloc(sizeof(microtcp_header_t));
  socket->state = LISTEN;
  uint8_t buff[MICROTCP_RECVBUF_LEN];

  // recieves the first syn packet from client side
  recvtemp = recvfrom(socket->sd, msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, &client_address_len);
  if (recvtemp < 0)
  {
    perror("Sadly No request from client\n");
    socket->state = INVALID;
    return 0;
  }
  uint32_t csum = ntohl(msgClient->checksum);
  uint32_t csum2;
  microtcp_header_t temp;
  temp.seq_number = msgClient->seq_number;
  temp.ack_number = msgClient->ack_number;
  temp.control = msgClient->control;
  for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
  {
    buff[i] = 0;
  }
  // copying all sent data from msgClient to buffer array used to calculate checksum(correct transmision)
  memcpy(buff, &temp, sizeof(microtcp_header_t));
  csum2 = crc32(buff, sizeof(buff));
  if (csum != csum2)
  { // checking that there is no error durng transmission using checksum
    perror("Error transmitting first packet,tcp handshake not established\n");
    socket->state = INVALID;
    return -1;
  }

  msgClient->control = ntohs(msgClient->control);
  if (msgClient->control != SYN)
  {
    perror("ERROR FIRST PACKET WASNT TYPE OF SYN\n");
    socket->state = INVALID;
    return -1;
  }
  microtcp_header_t msgServer; // creating 2nd packet of tcp handshake and first of server side
  // it is always a synack and we get our ACK number
  msgClient->seq_number = ntohl(msgClient->seq_number);
  msgServer.seq_number = htonl(rand() % 100 + 1);
  msgServer.control = htons(SYN_ACK);
  msgServer.ack_number = htonl(msgClient->seq_number + 1);
  msgServer.window = htons(MICROTCP_WIN_SIZE);
  msgServer.checksum = 0;
  for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
  {
    buff[i] = 0;
  }
  memcpy(buff, &msgServer, sizeof(microtcp_header_t));
  csum = crc32(buff, sizeof(buff));
  msgServer.checksum = htonl(csum); // creating checksum for error checking
  socket->init_win_size = MICROTCP_WIN_SIZE;
  // we send the 2nd packet to the client .
  if (sendto(socket->sd, (void *)&msgServer, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
  {
    perror("Could not send response back\n");
    socket->state = INVALID;
    return -1;
  }

  // we recieve the final packet of tcp
  //  its alweays an ack
  free(msgClient);
  msgClient = malloc(sizeof(microtcp_header_t));
  recvtemp = recvfrom(socket->sd, msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, &client_address_len);
  if (recvtemp < 0)
  {
    perror("Sadly No request from client\n");
    socket->state = INVALID;
    return 0;
  }
  csum = ntohl(msgClient->checksum);
  memset(&temp, 0, sizeof(microtcp_header_t));
  temp.seq_number = msgClient->seq_number;
  temp.ack_number = msgClient->ack_number;
  temp.control = msgClient->control;
  temp.window = msgClient->window;
  for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
  {
    buff[i] = 0;
  }
  memcpy(buff, &temp, sizeof(microtcp_header_t));
  csum2 = crc32(buff, sizeof(buff));
  if (csum != csum2)
  { // checking with checksum if its incorrect
    perror("Error transmitting third packet of  ,tcp handshake not established\n");
    socket->state = INVALID;
    return -1;
  }
  msgClient->control = ntohs(msgClient->control);
  if (msgClient->control != ACK)
  { // if the final packet of handshake isnt ack , connection cant be established
    perror("ERROR -3rd packet not ACK\n");
    socket->state = INVALID;
    return -1;
  }
  msgClient->seq_number = ntohl(msgClient->seq_number);
  msgClient->ack_number = ntohl(msgClient->ack_number);
  msgServer.ack_number = ntohl(msgServer.ack_number);
  msgServer.seq_number = ntohl(msgServer.seq_number);
  // important logic to check our handshake was correct ,explained by slides in project a explanation
  if (msgClient->seq_number != msgServer.ack_number || msgClient->ack_number != msgServer.seq_number + 1)
  {
    printf(" %d, %d, %d , %d", msgClient->seq_number, msgServer.ack_number, msgClient->ack_number, msgServer.seq_number + 1);
    perror("ERROR IN SYN OR ACK");
    socket->state = INVALID;
    return -1;
  }
  socket->ack_number = msgClient->ack_number;
  socket->seq_number = msgClient->seq_number + 1;
  socket->state = ESTABLISHED;
  free(msgClient);
  printf("[ACCEPT DONE] 3-way handshake completed\n");
  return 1;
}

int microtcp_shutdown(microtcp_sock_t *socket, int how) // terminates the connection is called always by the user first. (Client = 0 , Server = 1)
{
  microtcp_header_t msgClient, msgServer, temp;
  uint8_t buff[MICROTCP_RECVBUF_LEN];
  int recvtemp;
  uint32_t csum, csum2;

  if (how == 0)
  {
    msgClient.seq_number = htonl(rand() % 100 + 1); // initial seq number
    msgClient.ack_number = 0;
    msgClient.control = htons(FIN_ACK); // first packet of handshake is syn
    msgClient.checksum = 0;
    msgClient.window = 0;
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; i++)
    { // emptying buffer
      buff[i] = 0;
    }
    memcpy(buff, &msgClient, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    // printf("csum before sending is %u",csum);
    msgClient.checksum = htonl(csum); // adding checksum for error checking
    if (sendto(socket->sd, (void *)&msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->servAdd, *socket->serverAddrLen) < 0)
    {
      perror("Couldnt transmit first packet\n");
      socket->state = INVALID;
      return -1;
    }
    recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, 0, 0);
    if (recvtemp < 0)
    {
      perror("Sadly No request from client\n");
      socket->state = INVALID;
      return 0;
    }

    // Store the received checksum before modifying msgClient.checksum
    memcpy(&msgServer, buff, sizeof(microtcp_header_t));
    uint32_t receivedChecksum = ntohl(msgServer.checksum);
    // printf("Recived csum = %u\n",receivedChecksum);
    //  Modify msgClient.checksum for calculation
    msgServer.checksum = 0;
    // Verify the received packet
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgServer, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    //  Check if the calculated checksum matches the received checksum
    if (csum != receivedChecksum)
    {
      printf("Error transmitting first server packet, tcp handshake not established %u,%u\n", csum, receivedChecksum);
      socket->state = INVALID;
      return -1;
    }
    if (ntohs(msgServer.control) != ACK)
    {
      perror("Expected packet ack -ERROR");
      socket->state = INVALID;
      return -1;
    }
    socket->state = CLOSING_BY_HOST;
    memset(&msgServer, 0, sizeof(microtcp_header_t));
    memset(&buff, 0, sizeof(microtcp_header_t));
    recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, 0, 0);
    if (recvtemp < 0)
    {
      perror("Sadly No request from client\n");
      socket->state = INVALID;
      return 0;
    }
    memcpy(&msgServer, buff, sizeof(microtcp_header_t));
    receivedChecksum = ntohl(msgServer.checksum);
    // printf("Recived csum = %u\n",receivedChecksum);
    //  Modify msgClient.checksum for calculation
    msgServer.checksum = 0;
    // Verify the received packet
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgServer, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    //  Check if the calculated checksum matches the received checksum
    if (csum != receivedChecksum)
    {
      printf("Error transmitting first server packet, tcp handshake not established %u,%u\n", csum, receivedChecksum);
      socket->state = INVALID;
      return -1;
    }
    if (ntohs(msgServer.control) != FIN_ACK)
    {
      perror("Expected packet SYn_ack -ERROR");
      socket->state = INVALID;
      return -1;
    }
    msgClient.ack_number = htonl(ntohl(msgServer.seq_number) + 1);
    msgClient.seq_number = htonl(ntohl(msgClient.seq_number) + 1);
    msgClient.checksum = 0;
    msgClient.window = 0;
    msgClient.control = htons(ACK);
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgClient, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    msgClient.checksum = htonl(csum);
    if (sendto(socket->sd, (void *)&msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->servAdd, *socket->serverAddrLen) < 0)
    {
      perror("Could not send response back\n");
      socket->state = INVALID;
      return -1;
    }
    close(socket->sd);
    printf("CLIENT SUCCESFULLY TERMINATED\n");
  }
  else
  {
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    // waiting for the first packet to terminate
    recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, &client_address_len);
    if (recvtemp < 0)
    {
      perror("Sadly No request from client\n");
      socket->state = INVALID;
      return 0;
    }
    memcpy(&msgClient, buff, sizeof(microtcp_header_t));
    // Store the received checksum before modifying msgClient.checksum
    uint32_t receivedChecksum = ntohl(msgClient.checksum);

    // Modify msgClient.checksum for calculation
    msgClient.checksum = 0;

    // Verify the received packet
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgClient, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));

    // Check if the calculated checksum matches the received checksum
    if (csum != receivedChecksum)
    {
      printf("Error transmitting first packet%u,%u\n", csum, receivedChecksum);
      socket->state = INVALID;
      return -1;
    }
    // printf("c sum is correct its %u\n",csum);
    msgClient.control = ntohs(msgClient.control);
    if (msgClient.control != FIN_ACK)
    {
      perror("ERROR FIRST PACKET WASNT TYPE OF SYN_ACK\n");
      socket->state = INVALID;
      return -1;
    }
    socket->state = CLOSING_BY_PEER;
    msgClient.seq_number = ntohl(msgClient.seq_number);
    msgServer.seq_number = 0;
    msgServer.control = htons(ACK);
    msgServer.ack_number = htonl(msgClient.seq_number + 1);
    msgServer.checksum = 0;
    msgServer.window = 0;
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgServer, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    // printf("csum before sending is %u\n",csum);
    msgServer.checksum = htonl(csum); // creating checksum for error checking
    // we send the 2nd packet to the client .
    if (sendto(socket->sd, (void *)&msgServer, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
    {
      perror("Could not send response back\n");
      socket->state = INVALID;
      return -1;
    }
    msgServer.seq_number = htonl(rand() % 10 + 1);
    msgServer.control = htons(FIN_ACK);
    msgServer.checksum = 0;
    msgServer.window = 0;
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgServer, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    // printf("csum before sending is %u\n",csum);
    msgServer.checksum = htonl(csum); // creating checksum for error checking
    // we send the 2nd packet to the client .
    if (sendto(socket->sd, (void *)&msgServer, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
    {
      perror("Could not send response back\n");
      socket->state = INVALID;
      return -1;
    }
    memset(&msgClient, 0, sizeof(microtcp_header_t));
    memset(&buff, 0, sizeof(microtcp_header_t));
    recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, 0, 0);
    if (recvtemp < 0)
    {
      perror("Sadly No request from client\n");
      socket->state = INVALID;
      return 0;
    }
    memcpy(&msgClient, buff, sizeof(microtcp_header_t));
    receivedChecksum = ntohl(msgClient.checksum);
    // printf("Received csum = %u\n",receivedChecksum);
    // Modify msgClient.checksum for calculation
    msgClient.checksum = 0;
    // Verify the received packet
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgClient, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    // printf("calc csum = %u\n",csum);
    // Check if the calculated checksum matches the received checksum
    if (csum != receivedChecksum)
    {
      printf("Error transmitting first server packet, tcp handshake not established %u,%u\n", csum, receivedChecksum);
      socket->state = INVALID;
      return -1;
    }
    if (ntohs(msgClient.control) != ACK)
    {
      perror("Expected packet ack -ERROR");
      socket->state = INVALID;
      return -1;
    }
    msgClient.seq_number = ntohl(msgClient.seq_number);
    msgClient.ack_number = ntohl(msgClient.ack_number);
    msgServer.seq_number = ntohl(msgServer.seq_number);
    msgServer.ack_number = ntohl(msgServer.ack_number);
    if (msgClient.seq_number != msgServer.ack_number || msgClient.ack_number != msgServer.seq_number + 1)
    {
      perror("ERROR IN FINAL ACK AND SEQS");
      socket->state = INVALID;
      return -1;
    }
    close(socket->sd);
    printf("Connection closed successfully\n");
  }

  socket->state = CLOSED;
  return 1;
}


// new shutdown, is called by server when it is in recv mode and find fin ack packet
int microtcp_shutdown2(microtcp_sock_t *socket, int how) // terminates the connection is called always by the user first. (Client = 0 , Server = 1)
{
  microtcp_header_t msgClient, msgServer, temp;
  uint8_t buff[MICROTCP_RECVBUF_LEN];
  int recvtemp;
  uint32_t csum, csum2;

  if (how == 0)  //client side shutdown
  {
    if (socket->state != CLOSING_BY_PEER)
    {
      recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, 0, 0); //recieves first packet  of termination 
      if (recvtemp < 0)
      {
        perror("Sadly No request from client\n");
        socket->state = INVALID;
        return 0;
      }

      // Store the received checksum before modifying msgClient.checksum
      memcpy(&msgServer, buff, sizeof(microtcp_header_t));
      uint32_t receivedChecksum = ntohl(msgServer.checksum);
      // printf("Recived csum = %u\n",receivedChecksum);
      //  Modify msgClient.checksum for calculation
      msgServer.checksum = 0;
      // Verify the received packet
      for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
      {
        buff[i] = 0;
      }
      memcpy(buff, &msgServer, sizeof(microtcp_header_t));
      csum = crc32(buff, sizeof(microtcp_header_t));
      //  Check if the calculated checksum matches the received checksum
      if (csum != receivedChecksum)  //checksum check 
      {
        printf("Error transmitting first server packet, tcp handshake not established %u,%u\n", csum, receivedChecksum);
        socket->state = INVALID;
        return -1;
      }
      if (ntohs(msgServer.control) != ACK) // is ack check 
      {
        perror("Expected packet ack -ERROR");
        socket->state = INVALID;
        return -1;
      }
      socket->state = CLOSING_BY_HOST;  // setting socket state 
      socket->seq_number = ntohl(msgServer.ack_number);
      memset(&msgServer, 0, sizeof(microtcp_header_t));
      memset(&buff, 0, sizeof(microtcp_header_t));
      recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, 0, 0);  // getting 2nd packet from server side for termination 
      if (recvtemp < 0)
      {
        perror("Sadly No request from client\n");
        socket->state = INVALID;
        return 0;
      }
      memcpy(&msgServer, buff, sizeof(microtcp_header_t));
      receivedChecksum = ntohl(msgServer.checksum);
      // printf("Recived csum = %u\n",receivedChecksum);
      //  Modify msgClient.checksum for calculation
      msgServer.checksum = 0;
      // Verify the received packet
      for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
      {
        buff[i] = 0;
      }
      memcpy(buff, &msgServer, sizeof(microtcp_header_t));
      csum = crc32(buff, sizeof(microtcp_header_t));
      // printf("calc csum = %u\n",csum);
      //  Check if the calculated checksum matches the received checksum
      if (csum != receivedChecksum)
      {
        printf("Error transmitting first server packet, tcp handshake not established %u,%u\n", csum, receivedChecksum);
        socket->state = INVALID;
        return -1;
      }
      if (ntohs(msgServer.control) != FIN_ACK)
      {
        perror("Expected packet SYn_ack -ERROR");
        socket->state = INVALID;
        return -1;
      }
      socket->ack_number = htonl(ntohl(msgServer.seq_number)+1);
    }

    msgClient.ack_number = htonl(ntohl(socket->ack_number) );   //getting the correct seq and acks from our socket 
    msgClient.seq_number = htonl(ntohl(socket->seq_number) );
    msgClient.checksum = 0;
    msgClient.window = 0;
    msgClient.control = htons(ACK);
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgClient, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    msgClient.checksum = htonl(csum);
    if (sendto(socket->sd, (void *)&msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->servAdd, *socket->serverAddrLen) < 0)
    {
      perror("Could not send response back\n");
      socket->state = INVALID;
      return -1;
    }
    close(socket->sd);
    printf("CLIENT SUCCESFULLY TERMINATED\n");
  }
  else  // server side shutdown 
  {
    struct sockaddr_in client_address;
    socklen_t client_address_len = sizeof(client_address);
    // waiting for the first packet to terminate
    // Modify msgClient.checksum for calculation
    msgClient.checksum = 0;

    socket->state = CLOSING_BY_PEER;  //changing socket's state 
    msgServer.seq_number = 0;
    msgServer.control = htons(ACK);  //first server packet is ack 
    msgServer.ack_number = htonl(socket->ack_number);
    msgServer.checksum = 0;
    msgServer.window = 0;
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgServer, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    // printf("csum before sending is %u\n",csum);
    msgServer.checksum = htonl(csum); // creating checksum for error checking
    // we send the 1st  packet to the client .
    if (sendto(socket->sd, (void *)&msgServer, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
    {
      perror("Could not send response back\n");
      socket->state = INVALID;
      return -1;
    }
    msgServer.seq_number = htonl(rand() % 10 + 1);  // creating seq number for server side 
    socket->seq_number = htonl( ntohl(msgServer.seq_number));
    msgServer.control = htons(FIN_ACK);
    msgServer.checksum = 0;
    msgServer.window = 0;
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgServer, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    msgServer.checksum = htonl(csum); // creating checksum for error checking
    // we send the 2nd packet to the client .
    if (sendto(socket->sd, (void *)&msgServer, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
    {
      perror("Could not send response back\n");
      socket->state = INVALID;
      return -1;
    }
    memset(&msgClient, 0, sizeof(microtcp_header_t));
    memset(&buff, 0, sizeof(microtcp_header_t));
    recvtemp = recvfrom(socket->sd, buff, sizeof(microtcp_header_t), 0, 0, 0);
    if (recvtemp < 0)
    {
      perror("Sadly No request from client\n");
      socket->state = INVALID;
      return 0;
    }
    memcpy(&msgClient, buff, sizeof(microtcp_header_t));
    csum2 = ntohl(msgClient.checksum);
    // printf("Received csum = %u\n",receivedChecksum);
    // Modify msgClient.checksum for calculation
    msgClient.checksum = 0;
    // Verify the received packet
    for (int i = 0; i < MICROTCP_RECVBUF_LEN; ++i)
    {
      buff[i] = 0;
    }
    memcpy(buff, &msgClient, sizeof(microtcp_header_t));
    csum = crc32(buff, sizeof(microtcp_header_t));
    // printf("calc csum = %u\n",csum);
    // Check if the calculated checksum matches the received checksum
    if (csum != csum2)
    {
      printf("Error transmitting first server packet, tcp handshake not established %u,%u\n", csum, csum2);
      socket->state = INVALID;
      return -1;
    }
    if (ntohs(msgClient.control) != ACK)
    {
      printf("Expected packet ack -ERROR- IT IS %u", (unsigned int)ntohs(msgClient.control));
      socket->state = INVALID;
      return -1;
    }
    msgClient.seq_number = ntohl(msgClient.seq_number); // preparing the numbers 
    msgClient.ack_number = ntohl(msgClient.ack_number);
    msgServer.seq_number = ntohl(socket->seq_number);
    msgServer.ack_number = ntohl(socket->ack_number);
    if (msgClient.seq_number != msgServer.ack_number || msgClient.ack_number != msgServer.seq_number + 1)
    {
      perror("ERROR IN FINAL ACK AND SEQS");

      // Printing the values using printf
      printf("Client Seq Number: %hu\n", msgClient.seq_number);
      printf("Server Ack Number: %hu\n", msgServer.ack_number);
      printf("Client Ack Number: %hu\n", msgClient.ack_number);
      printf("Server Seq Number + 1: %hu\n", msgServer.seq_number + 1);

      socket->state = INVALID;
      return -1;
    }

    close(socket->sd);
    printf("Connection closed successfully\n");  
  }

  socket->state = CLOSED;
  return 1;
}
ssize_t microtcp_send(microtcp_sock_t *socket, const void *buffer, size_t length, int flags)  // function for sending data - Client side 
{
  uint8_t buff[MICROTCP_MSS + sizeof(microtcp_header_t)];  // used for storing data
  microtcp_header_t header; // used for sending and recieving headers
  size_t data_sent = 0; //data sent in this function instance
  size_t curr_data_sent = 0; // data sent on loop
  size_t verified_data = 0; // data that has been acked by server
  enum condition check; // brain of tcp . Handles timeouts , duplicates, slow start , congestion control 
  uint64_t chunks;  // chunk of data 
  size_t previous_ack = 0;  //last packet acked by server
  int duplicates = 0; // how many times we have seen the last ack
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
  uint64_t bytes_to_send; //decides how much data we can send 
  uint64_t i; // very usefull for deciding how many packets back we should go 
  uint64_t memptr; //important pointer to memory
  size_t seq = socket->seq_number; //seq 2 send 
  size_t initial_seq = seq; // starting seq number
  size_t remaining = length - data_sent; //remaining data to send 
  while (data_sent < length)
  {
    curr_data_sent = 0;
    verified_data = 0;
    check = CONG_SLOW; // starting condition 
    size_t bytes_to_send = minimum(socket->cwnd, socket->curr_win_size, remaining); // decides how much packets to send 
    chunks = bytes_to_send / MICROTCP_MSS; //how we calculate number of chunks 
    for (i = 0UL; i < chunks; ++i)
    {
      memptr = (uint64_t)(buffer) + (i * MICROTCP_MSS); // buffer goes to current chunk 
      //preparing packet 
      header.seq_number = htonl(seq);
      header.control = htons(SYN);
      header.window = htons(MICROTCP_RECVBUF_LEN - socket->buf_fill_level);  
      header.data_len = htonl(MICROTCP_MSS);
      header.checksum = htonl(crc32(memptr, MICROTCP_MSS));
      memcpy(buff, &header, sizeof(microtcp_header_t));
      memcpy(buff + sizeof(microtcp_header_t), (void *)(memptr), MICROTCP_MSS);
      if (sendto(socket->sd, buff, MICROTCP_MSS + sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->servAdd, *socket->serverAddrLen) < 1) //sending it to server 
      {
        perror("error transmitting packet\n");
        return EXIT_FAILURE;
      }
      socket->seq_number = seq; // saving seq number 
      ++seq; // next seq we will send 
    }
    data_sent = data_sent + i * MICROTCP_MSS;  //total data sent 
    remaining = remaining - data_sent; // remaining data sent 
    if (bytes_to_send % (MICROTCP_MSS)) // the same as above but just for the last semifilled chunk , maybe there is one , maybe not 
    {
      memptr = (uint64_t)(buffer) + (i * MICROTCP_MSS);
      header.seq_number = htonl(seq);
      header.control = htons(SYN);
      header.window = htons(MICROTCP_RECVBUF_LEN - socket->buf_fill_level);
      header.data_len = htonl(bytes_to_send % (MICROTCP_MSS));
      header.checksum = htonl(crc32(memptr, bytes_to_send % (MICROTCP_MSS)));
      memcpy(buff, &header, sizeof(microtcp_header_t));
      memcpy(buff + sizeof(microtcp_header_t), (void *)(memptr), bytes_to_send % (MICROTCP_MSS));
      ++chunks;
      if (sendto(socket->sd, buff, bytes_to_send % (MICROTCP_MSS) + sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->servAdd, *socket->serverAddrLen) < 1)
      {
        perror("error transmitting packet\n");
        return EXIT_FAILURE;
      }
      data_sent += MICROTCP_MSS;
      socket->seq_number = seq;
      ++seq;
    }
    for (i = 0UL; i < chunks; ++i) //time to listen for the server's response 
    {
      if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
      {
        perror("Set Timeout\n");
        socket->state = INVALID;
        return 0;
      }
      if (recvfrom(socket->sd, &header, sizeof(microtcp_header_t), 0, NULL, NULL) < 0)
      {
        perror("TIMEOUT HAPPENED\n"); //timeout happened , we leave from loop , and go straight to timeout condition
        check = TIMEOUT; // timeout condition 
        i--; // go back to the last correct ack
        break;
      }
      else
      {
        socket->curr_win_size += header.window;  // updating window size 
        if (previous_ack == header.ack_number) //duplicate ack 
        {
          ++duplicates;
          if (duplicates == 3)
          {
            check = DUPLICATE3;
            duplicates = 0;
            break;
          }
          i--;
        }
        else
        {
          previous_ack = header.ack_number;  
          if (previous_ack == initial_seq + i) //correct ack recieved 
          {
            verified_data += verified_data + header.data_len;
            if (socket->cwnd <= socket->ssthresh) // slow start
              socket->cwnd = socket->cwnd + MICROTCP_MSS;
            else // congestion avoidance
              socket->cwnd = socket->cwnd + 1;
            duplicates = 0;
            check = CONG_SLOW;
          }
        }
      }
    }
    if (check == TIMEOUT)  // timeout condition 
    {
      socket->ssthresh = socket->cwnd / 2;
      socket->cwnd = minimum(MICROTCP_MSS, socket->ssthresh, MICROTCP_RECVBUF_LEN);
      seq = socket->seq_number - chunks + i + 1;
      data_sent = data_sent - curr_data_sent + verified_data;
      remaining -= verified_data;
      if(socket->cwnd == 0){//to never stop
				socket->cwnd = 1;
			}
    }
    else if (check == DUPLICATE3) //fast retransmit condition 
    {
      socket->ssthresh = socket->cwnd / 2;
      socket->cwnd = socket->cwnd / 2 + 1;
      remaining -= verified_data;
      seq = socket->seq_number - chunks + i + 1;
      data_sent = data_sent - curr_data_sent + verified_data;
      remaining -= verified_data;
    }
    else if (check == CONG_SLOW) //original condition 
    {
      if (curr_data_sent == verified_data) // we have recieved all the acks 
      {
        remaining = remaining - curr_data_sent;
      }
      else
      {
        seq = seq - chunks; // error with acks , lost data. Sending data from the start 
        data_sent -= curr_data_sent;
      }
    }
    socket->seq_number = seq;
  }
  return data_sent;
}

ssize_t microtcp_recv(microtcp_sock_t *socket, void *buffer, size_t length, int flags) //recieve function , used by server 
{
  uint8_t buff[MICROTCP_MSS + sizeof(microtcp_header_t)]; //buffer for storing data 
  microtcp_header_t header; // used for sending and recieving data 
  uint64_t total_bytes_read = 0; // total bytes read
  int indexed_bytes; //bytes currently in this recv buffered / indexed
  int totalIndexedBytes = 0; // number of indexed bytes 
  struct sockaddr_in client_address;
  socklen_t client_address_len = sizeof(client_address);
  struct timeval timeout;
  timeout.tv_sec = 0;
  timeout.tv_usec = MICROTCP_ACK_TIMEOUT_US;
  size_t next_seq = socket->ack_number;
  size_t next_seq_2 = socket->seq_number;

  while (1)  // exits only when storing buffer full, or fin_ack packet recieved
  {
    if (setsockopt(socket->sd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(struct timeval)) < 0)
    {
      perror("Set Timeout\n");
      socket->state = INVALID;
      return 0;
    }
    indexed_bytes = recvfrom(socket->sd, buff, MICROTCP_MSS + sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, &client_address_len); // bytes recieved 
    if (indexed_bytes == -1) //timeout condition
    {
      header.window = htons(MICROTCP_RECVBUF_LEN); 
      header.control = htons(ACK);
      header.ack_number = htonl(next_seq);
      if (sendto(socket->sd, (void *)&header, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0) //fast retransmit 
      {
        perror("couldnt transmit packet\n");
        return EXIT_FAILURE;
      }
    }
    else if (indexed_bytes == 0) //gracefull exit 
    {
      break;
    }
    else
    {
      memcpy(&header, buff, sizeof(microtcp_header_t));
      header.seq_number = ntohl(header.seq_number);
      header.ack_number = ntohl(header.ack_number);
      header.control = ntohs(header.control); // Make sure you convert this from network to host byte order!
      header.window = ntohs(header.window);
      header.data_len = ntohl(header.data_len);
      header.checksum = ntohl(header.checksum);

      // final packet from client start shutdown and exit recv 
      if (header.control == FIN_ACK)
      {
        printf("entered inside\n");
        socket->ack_number =  htonl(ntohl(header.seq_number)+1);
        socket->state = CLOSING_BY_PEER;
        return total_bytes_read;
      }
      if (header.seq_number == next_seq) //correct packet recieved 
      {
        // Print the values of pointers and lengths before memcpy
        if (header.data_len > indexed_bytes - sizeof(microtcp_header_t))
        {
          fprintf(stderr, "Header data length (%u) is larger than the received data size (%d).\n", header.data_len, indexed_bytes - sizeof(microtcp_header_t));
          // Handle error, maybe break or continue to the next iteration
        }
        if (total_bytes_read + header.data_len > length)
        {
          fprintf(stderr, "Not enough space in the user buffer. Can't copy %u bytes.\n", header.data_len);
          // Handle error, maybe break or continue to the next iteration
        }
        memcpy(buffer + total_bytes_read, buff + sizeof(microtcp_header_t), header.data_len);
        total_bytes_read += header.data_len;
        totalIndexedBytes += header.data_len;
        ++next_seq;
        socket->ack_number = next_seq; //update next seq number 
        header.ack_number = htonl(next_seq);
        header.control = htons(ACK);
        header.window = htonl(MICROTCP_RECVBUF_LEN);
        header.checksum = htonl(0);
        header.data_len = htonl(0);
        if (sendto(socket->sd, (void *)&header, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
        {
          perror("couldnt transmit packet\n");
          return EXIT_FAILURE;
        }
      }
      else //wrong packet recieved send retrasnmit 
      {
        socket->ack_number = next_seq;
        header.ack_number = htonl(next_seq);
        header.control = htons(ACK);
        header.window = htonl(MICROTCP_RECVBUF_LEN);
        header.checksum = htonl(0);
        header.data_len = htonl(0);
        if (sendto(socket->sd, (void *)&header, sizeof(microtcp_header_t), 0, (struct sockaddr *)&client_address, client_address_len) < 0)
        {
          perror("could not transmit packet\n");
          return EXIT_FAILURE;
        }
      }
    }

    if (length - totalIndexedBytes <= 1500){ //IMPORTANT ! if buffer almost full exit and call recv again .
      break;
    }
  }
  return total_bytes_read;
}

ssize_t minimum(size_t a, size_t b, size_t c) // returns minimin from 3 vars 
{
  size_t min;
  min = a;
  if (b < min)
  {
    min = b;
  }
  if (c < min)
  {
    min = c;
  }
  return min;
}
ssize_t minimum2(ssize_t a, ssize_t b)// returns minimin from 2 vars 
{
  if (a < b)
  {
    return a;
  }
  else
  {
    return b;
  }
}

int init_shutdown(microtcp_sock_t *socket) // client side function sends first packet of termination 
{
  microtcp_header_t msgClient;
  msgClient.seq_number =  htonl(socket->seq_number);
  msgClient.control = htons(FIN_ACK); // first packet of handshake is syn
  msgClient.checksum = 0;
  msgClient.window = 0;
  printf("sending final packet\n");                                                                                                         // adding checksum for error checking
  if (sendto(socket->sd, (void *)&msgClient, sizeof(microtcp_header_t), 0, (struct sockaddr *)socket->servAdd, *socket->serverAddrLen) < 0) // sending first packet of handshake
  {
    perror("Couldnt transmit first packet\n");
    socket->state = INVALID;
    return -1;
  }
}