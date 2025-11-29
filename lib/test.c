ssize_t microtcp_recv(microtcp_sock_t * __restrict__ socket, void * __restrict__ buffer, size_t length, int flags)
{
	uint8_t tbuff[MICROTCP_MSS + MICROTCP_HEADER_SIZE];
	microtcp_header_t tcph;

	int64_t total_bytes_read;
	int64_t bytes_read;

	int sockfd;
	int frag;


	if ( !socket ) {

		errno = EINVAL;
		return -(EXIT_FAILURE);
	}

	if ( (socket->state == INVALID) || (socket->state >= CLOSING_BY_PEER) ) {

		errno = EINVAL;
		return -(EXIT_FAILURE);
	}


	total_bytes_read = 0L;
	sockfd = socket->sd;

rflag0:
	check( total_bytes_read = recv(sockfd, tbuff, length, 0) );
	memcpy(&tcph, tbuff, MICROTCP_HEADER_SIZE);
	print_tcp_header(socket,&tcph);

	_ntoh_recvd_tcph(tcph);

	// Fast Retransmit
	if ( tcph.seq_number > socket->ack_number ) {

		LOG_DEBUG("Reordering\n");  // packet that was read is actually discarded!
		_preapre_send_tcph(socket, &tcph, CTRL_ACK, NULL, 0U);
		check( send(sockfd, &tcph, MICROTCP_HEADER_SIZE, 0) );

		/** TODO: Packet reordeing could also be performed here,
		 * thus achieving better performance.
		 */

		goto rflag0;
	}
	else if ( tcph.control & CTRL_FIN ) {  // termination

		microtcp_shutdown(socket, SHUTDOWN_SERVER);
		return -1L;
	}
	else if ( tcph.seq_number < socket->ack_number )  // skip duplicate packets (during TIMEOUT)
		goto rflag0;

	if ( !tcph.data_len )  // zero length packet
		return 0L;

	memcpy(buffer, tbuff + MICROTCP_HEADER_SIZE, tcph.data_len);

	total_bytes_read -= MICROTCP_HEADER_SIZE;
	socket->ack_number += tcph.data_len;
	tcph.ack_number = socket->ack_number;
	tcph.seq_number = socket->seq_number;
	frag = tcph.control & FRAGMENT;

	_preapre_send_tcph(socket, &tcph, CTRL_ACK, NULL, 0U);
	check( send(sockfd, &tcph, MICROTCP_HEADER_SIZE, 0) );

	if ( !frag )  // no fragmentation case
		return total_bytes_read;

	// fragmentation case
	tbuff[total_bytes_read - 1L];
	bytes_read = total_bytes_read;

	do {

		tbuff[bytes_read - 1L] = 0;

		check( bytes_read = recv(sockfd, tbuff, MICROTCP_MSS + MICROTCP_HEADER_SIZE, 0) );
		memcpy(&tcph, tbuff, MICROTCP_HEADER_SIZE);
		_ntoh_recvd_tcph(tcph);
		memcpy(buffer + total_bytes_read, tbuff + MICROTCP_HEADER_SIZE, tcph.data_len);

		total_bytes_read += bytes_read - MICROTCP_HEADER_SIZE;
		socket->ack_number += tcph.data_len;
		tcph.seq_number = socket->seq_number;
		tcph.ack_number = socket->ack_number;
		frag = tcph.control & FRAGMENT;

		_preapre_send_tcph(socket, &tcph, CTRL_ACK, NULL, 0U);
		check( send(sockfd, &tcph, MICROTCP_HEADER_SIZE, 0) );

	} while ( !frag );


	return total_bytes_read;
}