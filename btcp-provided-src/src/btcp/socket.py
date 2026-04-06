from btcp.btcp_socket import BTCPSocket, BTCPStates
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import time
import logging
import random

logger = logging.getLogger(__name__)

class Socket(BTCPSocket):
    """Merged bTCP socket capable of acting as client or server with bidirectional reliable transfer."""

    # =========================================================================================== #
    # =========================================================================================== #
    # Network Layer Side 
    # =========================================================================================== #    
    # =========================================================================================== #

   
    # =========================================================================================== #
    # COMMON 
    # =========================================================================================== #

    def __init__(self, window, timeout, isn=None):
        logger.debug("__init__() called.")

        super().__init__(window, timeout, isn)

        self._recvbuf = queue.Queue(maxsize=1000)
        self._sendbuf = queue.Queue(maxsize=1000)

        # Sender side
        self._send_base = self._seqnum
        self._next_seqnum = self._seqnum
        self._send_window = self._window
        self._unacked = {}

        # Receiver Side
        self._expected_seqnum = None
        self._reorder_buffer = {}
        self._receive_window = self._window

        # Remote ISN
        self._remote_isn = 0

        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT) # Default to Client. Calling accept or connect should still works
        self._lossy_layer.start_network_thread()

    def _setup_lossy_layer(self, local_ip, local_port, remote_ip, remote_port):     
        if self._lossy_layer is not None:
            self._lossy_layer.destroy()

        self._lossy_layer = LossyLayer(self, local_ip, local_port, remote_ip, remote_port)
        self._lossy_layer.start_network_thread()

    def lossy_layer_segment_received(self, segment):
        logger.debug("Lossy_layer_segment_received called.")

        result = self._common_segment_processing(segment)
        if result is None:
            return
        
        seqnum, acknum, syn, ack, fin, window, length, data = result

        if ack and window > 0:
            self._send_window = window

        match self._state:
            case BTCPStates.CLOSED:
                self._closed_segment_received(result)
            case BTCPStates.SYN_SENT:
                self._syn_sent_segment_received(result)
            case BTCPStates.SYN_RCVD:
                self._syn_rcvd_segment_received(result)
            case BTCPStates.ESTABLISHED:
                self._established_segment_received(result)
            case BTCPStates.FIN_SENT:
                self._fin_sent_segment_received(result)
            case BTCPStates.CLOSING:
                self._closing_segment_received(result)
            case _:
                logger.warning(f"Ignoring segment in state {self._state.name}")
        
        current_time = time.monotonic_ns()
        self._check_retransmissions(current_time=current_time)

    def lossy_layer_tick(self):
        current_time = time.monotonic_ns()
        self._check_retransmissions(current_time=current_time)
        self._send_pending_data()

    # =========================================================================================== #
    # Lossy Layer Functions
    # =========================================================================================== #

    def _closed_segment_received(self, result):
        """Helper method handling received segment in CLOSED state"""
        seqnum, acknum, syn, ack, fin, window, length, data = result

        logger.debug("_closed_segment_received called")
        logger.debug("syn %i, ack %i, fin %i", syn, ack, fin)
        if syn and not ack and not fin:
            logger.info(f"Received SYN from client (seq={seqnum})")
            self._state = BTCPStates.SYN_RCVD
            self._remote_isn = seqnum                           # store client's ISN (x)
            self._expected_seqnum = (seqnum + 1) % 65536
            self._send_syn_ack(acknum=seqnum + 1)     # ack = x + 1
            logger.debug("Closed segment received and sent SYN|ACK")
        else:
            logger.debug("Ignored non-SYN segment in CLOSED state")

    def _syn_sent_segment_received(self, result):
        """Helper method handling received segment in SYN_SENT state"""

        seqnum, acknum, syn, ack, fin, window, length, data = result

        if syn and ack:
            expected_ack = (self._seqnum + 1) % 65536
            if acknum == expected_ack:
                logger.info("Received SYN|ACK from server")
        
                self._state = BTCPStates.ESTABLISHED
                self._send_window = window
                self._seqnum = expected_ack
                self._send_base = expected_ack

                self._next_seqnum = expected_ack     
                self._expected_seqnum = (seqnum + 1) % 65536

                self._send_ack(acknum=seqnum + 1)
                logger.info("Handshake completed?")
                return True

        logger.info("Ignored unexpected segment in SYN_SENT")
        return False
    
    def _syn_rcvd_segment_received(self, result):
        """Helper method handling received segment in SYN_RCVD state"""
        
        seqnum, acknum, syn, ack, fin, window, length, data = result
        if ack and not syn and not fin:
            expected_ack = (self._seqnum + 1) % 65536
            if acknum == expected_ack:
                logger.info("Received final ACK of handhake")
                self._state = BTCPStates.ESTABLISHED
                self._next_seqnum = expected_ack
                self._send_base = expected_ack
                return True
        
        logger.debug("Ignored unexpected segment received by SERVER in SYN_RCVD")
        return False

    def _established_segment_received(self, result):    
        seqnum, acknum, syn, ack, fin, window, length, data = result

        if window > 0:
            self._send_window = window

        if fin:
            logger.info("Received FIN from server so closing")
            self._state = BTCPStates.CLOSING
            self._send_fin_ack()
            return True
        
        if length > 0:
            self._handle_incoming_data(seqnum, data)
            return
        
        if ack:
            self._process_acknowledgement(acknum, window)
            return True
        
        logger.debug("Ignored non-ACK/non-FIN segment in ESTABLISHED")
        return False 

    def _fin_sent_segment_received(self, result):
        """Helper method handling received segment in FIN_SENT state"""
        seqnum, acknum, syn, ack, fin, window, length, data = result

        if fin and ack:
            if acknum == (self._seqnum + 1) % 65536:
                logger.info("Received FIN|ACK from server so connection closing")
                self._state = BTCPStates.CLOSING
                self._send_ack(acknum=acknum)
                return True
        logger.debug("Ignored unexpected segment in FIN_SENT")
        return False


    def _closing_segment_received(self, result):
        seqnum, acknum, syn, ack, fin, window, length, data = result
        if ack:
            logger.info("Received final ACK so terminating")
            self._state = BTCPStates.CLOSED
            return True
        
        logger.debug("Ignored segment received by server in CLOSING")
        return False


    def _handle_incoming_data(self, seqnum, data):
        """Helper method handling received segment in ESTABLISHED state"""     
        delivered = False

        if seqnum == self._expected_seqnum:
            # Deliver data in order
            self._deliver_data(data)
            self._expected_seqnum = (self._expected_seqnum + 1) % 65536
            delivered = True

            # Check for buffered segments that are now in order
            while self._expected_seqnum in self._reorder_buffer:
                buffered_data = self._reorder_buffer.pop(self._expected_seqnum)
                self._deliver_data(buffered_data)
                self._expected_seqnum = (self._expected_seqnum + 1) % 65536
            
            # Send ACK for the received data
            
        elif (seqnum - self._expected_seqnum) % 65536 < 32768:
            # Out-of-order but within window - buffer it
            if seqnum not in self._reorder_buffer:
                self._reorder_buffer[seqnum] = data
                logger.debug(f"Buffered out-of-order segment seq={seqnum}")
                # Send duplicate ACK for expected sequence number
            else:
                logger.debug(f"Duplicate buffered segment seq={seqnum}")
        else:
            # Old packet - ignore but send ACK anyway
            logger.debug(f"Ignoring old segment seq={seqnum}")
        
        self._send_ack(acknum=self._expected_seqnum, window=self._receive_window)
        return delivered

    def _send_ack(self, acknum, window=None):
        """Helper function to send a pure ACK segment"""
        if window is None:
            window = self._receive_window
        # Build with wrong checksum
        header = self.build_segment_header(
            seqnum=self._seqnum, #acks without data do not advance seqnum
            acknum=acknum,
            syn_set=False,
            ack_set=True,
            fin_set=False,
            window=window,
            length=0,
            checksum=0
        )

        # Compute checksum
        segment = header + b'\x00' * PAYLOAD_SIZE
        checksum = self.in_cksum(segment)

        header = self.build_segment_header(
            seqnum=self._seqnum,
            acknum=acknum,
            syn_set=False,
            ack_set=True,
            fin_set=False,
            window=window,
            length=0,
            checksum=checksum
        )
        segment = header + b'\x00' * PAYLOAD_SIZE
        self._lossy_layer.send_segment(segment)
        logger.debug(f"Sent ACK with acknum={acknum}")

    # =========================================================================================== #
    # CLIENT 
    # =========================================================================================== #


    def _process_acknowledgement(self, acknum, window):
        logger.debug(f"Processing ACK for acknum={acknum}, advertised window={window}")
        if window > 0:
            self._send_window = window

        to_remove = []
        for seq in self._unacked:
            if (acknum - seq) % 65536 < 32768:
                to_remove.append(seq)
        
        for seq in to_remove:
            if seq in self._unacked:
                del self._unacked[seq]
                logger.debug(f"Segment seq={seq} acknowledged and removed from buffer")
        
        if to_remove:
            self._send_base = acknum
        
        self._send_pending_data()

    def _send_pending_data(self):
        while not self._sendbuf.empty():
            in_flight = (self._next_seqnum - self._send_base) % 65536
            if in_flight >= self._send_window:
                logger.debug(f"Send window full ({in_flight} / {self._send_window})")
                break

            try:
                chunk = self._sendbuf.get_nowait()
            except queue.Empty:
                break

            datalen = len(chunk)
            if datalen < PAYLOAD_SIZE:
                chunk = chunk + b'\x00' * (PAYLOAD_SIZE - datalen)
            
            header = self.build_segment_header(
                seqnum=self._next_seqnum,
                acknum=0,
                syn_set=False,
                ack_set=False,
                fin_set=False,
                window=self._send_window,
                length=datalen,
                checksum=0
            )

            segment = header + chunk
            checksum = self.in_cksum(segment)

            # Rebuild header with correct checksum
            header = self.build_segment_header(
                seqnum=self._next_seqnum,
                acknum=0,
                syn_set=False,
                ack_set=False,
                fin_set=False,
                window=self._send_window,
                length=datalen,
                checksum=checksum
            )
            segment = header + chunk

            self._lossy_layer.send_segment(segment)

            # Store for possible retransmission + record send time
            self._unacked[self._next_seqnum] = (segment, time.monotonic_ns())

            logger.info(f"Sent data segment seq={self._next_seqnum}, length={datalen}")

            self._next_seqnum = (self._next_seqnum + 1) % 65536

        if self._unacked:
            logger.debug(f"{len(self._unacked)} segments still unacknowledged")

    def _check_retransmissions(self, current_time):
        timeout_ns = self.timeout_nanosecs

        for seqnum, (segment, send_time) in list(self._unacked.items()):
            if current_time - send_time > timeout_ns:
                logger.warning(f"Timeout on segment seq={seqnum} - retransmitting")
                self._lossy_layer.send_segment(segment)

                self._unacked[seqnum] = (segment, current_time)
    # =========================================================================================== #
    # SERVER 
    # =========================================================================================== #

    def _deliver_data(self, data):
        try:
            self._recvbuf.put_nowait(data)
            logger.debug(f"Delivered {len(data)} bytes to recv buffer")
        except queue.Full:
            logger.warning("Receive buffer full so dropping data")

 
 
    # =========================================================================================== #
    # =========================================================================================== #
    # Application Layer Side 
    # =========================================================================================== #    
    # =========================================================================================== #

    def connect(self):
        """Perform the bTCP three-way handshake to establish a connection.

        connect should *block* (i.e. not return) until the connection has been
        successfully established or the connection attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the syn/ack from the server will be received
        in the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        Since Python uses duck typing, and Queues can handle mixed types,
        you could even use the same queue to send a "connect signal", then
        all data chunks, then a "shutdown signal", into the network thread.
        That will take some tricky handling, however.

        We do not think you will need more advanced thread synchronization in
        this project.
        """

        if self._state != BTCPStates.CLOSED:
            logger.error("Accept can only be called from the closed state")
            return


        self._setup_lossy_layer(CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        logger.debug("connect called")
        max_retries = 5
        retry_count = 0
        start_time = time.monotonic()

        while retry_count < max_retries:
            if time.monotonic() - start_time > self.timeout_secs:
                logger.error("Connection timeout reached")
                self._state = BTCPStates.CLOSED
                return

            self._state = BTCPStates.SYN_SENT

            header = self.build_segment_header(
                seqnum=self._seqnum,
                acknum=0,
                syn_set=True,
                ack_set=False,
                fin_set=False,
                window=self._send_window,
                length=0,
                checksum=0
            )
            segment = header + b'\x00' * PAYLOAD_SIZE
            checksum = self.in_cksum(segment)
            header = self.build_segment_header(
                seqnum=self._seqnum,
                acknum=0,
                syn_set=True,
                ack_set=False,
                fin_set=False,
                window=self._send_window,
                length=0,
                checksum=checksum
            )
            segment = header + b'\x00' * PAYLOAD_SIZE

            self._lossy_layer.send_segment(segment)
            logger.info(f"Sent SYN with seq={self._seqnum}")
            print("What the client is sending in BTCPClientSocket.connect:")
            print(self._common_segment_processing(segment))
            wait_start = time.monotonic()
            while self._state == BTCPStates.SYN_SENT:
                if time.monotonic() - wait_start > 0.1: #TODO: per-retry timeout
                    break
                time.sleep(0.05) # avoid busy waiting?
            
            logger.info("Current state in client is %s", self._state.name)
            if self._state == BTCPStates.ESTABLISHED:
                logger.info("Handshake completed succesfully")
                return

            retry_count += 1
            logger.warning(f"Handshake attempt {retry_count} failed, retrying...")
        
        logger.error("Max retries exceeded during connect")
        self._state = BTCPStates.CLOSED

    
    def accept(self):   
        """Accept and perform the bTCP three-way handshake to establish a
        connection.

        accept should *block* (i.e. not return) until a connection has been
        successfully established.  You will need some
        coordination between the application thread and the network thread for
        this, because the syn and final ack from the client will be received in
        the network thread.

        Hint: assigning to a boolean or enum attribute in thread A and reading
        it in a loop in thread B (preferably with a short sleep to avoid
        wasting a lot of CPU time) ensures that thread B will wait until the
        boolean or enum has the expected value. You can also put some kind of
        "signal" (e.g. BTCPSignals.CONNECT, or BTCPStates.FIN_SENT) in a Queue,
        and use a blocking get() on the other side to receive that signal.

        We do not think you will need more advanced thread synchronization in
        this project.
        """
        if self._state != BTCPStates.CLOSED:
            logger.error("Accept can only be called from the closed state")
            return

        self._setup_lossy_layer(SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        logger.debug("accept called")

        start_time = time.monotonic()

        while self._state != BTCPStates.ESTABLISHED:
            if time.monotonic() - start_time > self.timeout_secs:
                logger.error("Accept timeout reached")
                raise TimeoutError()
            time.sleep(0.05)

        logger.info("Connection accepted")
    
    def send(self, data):
        """Send data originating from the application in a reliable way to the
        server.

        This method should *NOT* block waiting for acknowledgement of the data.


        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "send" operates on a "send buffer".
        Once (part of) the data has been successfully put "in the send buffer",
        the send method returns the number of bytes it was able to put in the
        buffer. The actual sending of the data, i.e. turning it into segments
        and sending the segments into the lossy layer, happens *outside* of the
        send method (e.g. in the network thread).
        If the socket does not have enough buffer space available, it is up to
        the application to retry sending the bytes it was not able to buffer
        for sending.

        Again, you should feel free to deviate from how this usually works.
        However, you should *not* deviate from the behaviour of returning the
        amount of bytes you were actually able to send, regardless of whether
        you use a send buffer or actually send the segments here.

        Note that our rudimentary implementation here already chunks the data
        in maximum 1008-byte bytes objects because that's the maximum a segment
        can carry. If a chunk is smaller we do *not* pad it here, that gets
        done later.
        """
        if self._lossy_layer == None:
            logger.error("You haven't called connect first. Terminating.")
            return
        
        logger.debug("send called")

        if not data:
            return 0
        
        datalen = len(data)
        logger.debug("%i bytes passed to send()", datalen)

        sent_bytes = 0
        logger.info("Queueing data for transmission")
        try:
            while sent_bytes < datalen:
                chunk = data[sent_bytes:sent_bytes+PAYLOAD_SIZE]
                chunk_len = len(chunk)

                self._sendbuf.put_nowait(chunk)
                sent_bytes += chunk_len
        except queue.Full:
            logger.info("Send queue full.")
        logger.info("Managed to queue %i out of %i bytes for transmission",
                    sent_bytes,
                    datalen)
        
        try:
            self._send_pending_data()
        except Exception as e:
            logger.debug("Could not immediately send after queuing: %s", e)
        
        return sent_bytes
    
    def recv(self):
        """Return data that was received from the client to the application in
        a reliable way.

        If no data is available to return to the application, this method
        should block waiting for more data to arrive. If the connection has
        been terminated, this method should return with no data (e.g. an empty
        bytes b'').

        You are free to implement this however you like, but the following
        explanation may help to understand how sockets *usually* behave and you
        may choose to follow this concept as well:

        The way this usually works is that "recv" operates on a "receive
        buffer". Once data has been successfully received and acknowledged by
        the transport layer, it is put "in the receive buffer". A call to recv
        will simply return data already in the receive buffer to the
        application.  If no data is available at all, the method will block
        until at least *some* data can be returned.
        The actual receiving of the data, i.e. reading the segments, sending
        acknowledgements for them, reordering them, etc., happens *outside* of
        the recv method (e.g. in the network thread).
        Because of this blocking behaviour, an *empty* result from recv signals
        that the connection has been terminated.

        Again, you should feel free to deviate from how this usually works,
        e.g. by only returning the next available packet of data instead of
        everything in one go, but you do need to keep the behaviour that an
        *empty* response signals a disconnect.
        """

        logger.debug("recv called")
        
        # Check if connection is still established or closing
        if self._state == BTCPStates.CLOSED:
            logger.info("Connection already closed, returning empty bytes")
            return b''
        
        data = bytearray()
        logger.info("Retrieving data from receive queue")
        
        try:
            # Wait for at least one packet
            chunk = self._recvbuf.get(block=True, timeout=self.timeout_secs)
            data.extend(chunk)
            
            # Get any remaining packets without blocking
            while True:
                try:
                    data.extend(self._recvbuf.get_nowait())
                except queue.Empty:
                    break
                    
        except queue.Empty:
            # Timeout - check if connection is still alive
            if self._state == BTCPStates.CLOSING or self._state == BTCPStates.CLOSED:
                logger.info("Connection terminated, returning empty bytes")
                return b''
            else:
                # Still waiting for data
                logger.debug("No data available yet")
                return self.recv()  # Recursively wait
        
        logger.info(f"Returning {len(data)} bytes")
        return bytes(data)
    
    def shutdown(self):
        """Perform the bTCP three-way finish to shutdown the connection.

        shutdown should *block* (i.e. not return) until the connection has been
        successfully terminated or the disconnect attempt is aborted. You will
        need some coordination between the application thread and the network
        thread for this, because the fin/ack from the server will be received
        in the network thread.
        """
        logger.info("Starting bTCP connection termination (client-initiated shutdown)")
        
        if self._state != BTCPStates.ESTABLISHED:
            logger.warning(f"Shutdown called in state {self._state.name} so we're ignoring it")
            return
        
        max_retries = 5
        retry_count = 0
        start_time = time.monotonic()

        while retry_count < max_retries:
            if time.monotonic() - start_time > self.timeout_secs:
                logger.warning("Shutdown timeout reached - assuming server side is closed")
                self._state = BTCPStates.CLOSED
                return

            # Step 1: Send FIN
            self._state = BTCPStates.FIN_SENT
            header = self.build_segment_header(
                seqnum=self._seqnum,
                acknum=0,
                syn_set=False,
                ack_set=False,
                fin_set=True,
                window=self._send_window,
                length=0,
                checksum=0
            )
            segment = header + b'\x00' * PAYLOAD_SIZE
            checksum = self.in_cksum(segment)

            header = self.build_segment_header(
                seqnum=self._seqnum,
                acknum=0,
                syn_set=False,
                ack_set=False,
                fin_set=True,
                window=self._send_window,
                length=0,
                checksum=checksum
            )
            segment = header + b'\x00' * PAYLOAD_SIZE

            self._lossy_layer.send_segment(segment)
            logger.info(f"Sent FIN (seq={self._seqnum}), attempt {retry_count+1}")

            wait_start = time.monotonic()
            while self._state == BTCPStates.FIN_SENT:
                if time.monotonic() - wait_start > 0.1: #TODO: per-retry timeout
                    break
                time.sleep(0.05)

            if self._state == BTCPStates.CLOSING or self._state == BTCPStates.CLOSED:
                # We received FIN|ACK and sent final ACK (or timed out gracefully)
                logger.info("Connection termination completed")
                return
            
            retry_count += 1
            logger.warning(f"FIN attempt {retry_count} failed, retrying")

        logger.warning("Max retries exceeded during shutdown so we're assuming server is closed")
        self._state = BTCPStates.CLOSED

    def close(self):
        """Cleans up any internal state by at least destroying the instance of
        the lossy layer in use. Also called by the destructor of this socket.

        Do not confuse with shutdown, which disconnects the connection.
        close destroys *local* resources, and should only be called *after*
        shutdown.

        Probably does not need to be modified, but if you do, be careful to
        gate all calls to destroy resources with checks that destruction is
        valid at this point -- this method will also be called by the
        destructor itself. The easiest way of doing this is shown by the
        existing code:
            1. check whether the reference to the resource is not None.
                2. if so, destroy the resource.
            3. set the reference to None.
        """
        logger.debug("close called")
        ll = getattr(self, "_lossy_layer", None)
        if ll != None:
            ll.destroy()
            self._lossy_layer = None

    def __del__(self):
        """Destructor. Do not modify."""
        logger.debug("__del__ called")
        self.close()