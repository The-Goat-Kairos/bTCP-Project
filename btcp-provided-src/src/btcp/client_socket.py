from btcp.btcp_socket import BTCPSocket, BTCPStates, raise_NotImplementedError
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import logging
import random
import time


logger = logging.getLogger(__name__)


class BTCPClientSocket(BTCPSocket):
    """bTCP client socket
    A client application makes use of the services provided by bTCP by calling
    connect, send, shutdown, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPClientSocket.lossy_layer_segment_received, lossy_layer_tick).

    Your implementation will operate in two threads, the network thread,
    where the lossy layer "lives" and where your callbacks will be called from,
    and the application thread, where the application calls connect, send, etc.
    This means you will need some thread-safe information passing between
    network thread and application thread.
    Writing a boolean or enum attribute in one thread and reading it in a loop
    in another thread should be sufficient to signal state changes.
    Lists, however, are not thread safe, so to pass data and segments around
    you probably want to use queues*, or a similar thread safe collection.

    * See <https://docs.python.org/3/library/queue.html>
    """


    def __init__(self, window, timeout, isn=None):
        """Constructor for the bTCP client socket. Allocates local resources
        and starts an instance of the Lossy Layer.
        """
        logger.debug("__init__ called")
        super().__init__(window, timeout, isn)
        self._lossy_layer = LossyLayer(self, CLIENT_IP, CLIENT_PORT, SERVER_IP, SERVER_PORT)

        # The data buffer used by send() to send data from the application
        # thread into the network thread. Bounded in size.
        self._sendbuf = queue.Queue(maxsize=1000)
        self._lossy_layer.start_network_thread()

        self._send_base = self._seqnum
        self._next_seqnum = self._seqnum
        self._send_window = self._window
        self._unacked = {}
        self._last_retransmit_check = time.monotonic_ns()

        logger.info("Socket initialized with sendbuf size 1000")


    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival.                                                            ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn/ack during handshake
            - receiving ack and registering the corresponding segment as being
              acknowledged
            - receiving fin/ack during termination
            - any other handling of the header received from the server

        Remember, we expect you to implement this *as a state machine!*
        You have quite a bit of freedom in how you do this, but we at least
        expect you to *keep track of the state the protocol is in*,
        *perform the appropriate state transitions based on events*, and
        *alter behaviour based on that state*.

        So when you receive the segment, do the processing that is common
        for all states (verifying the checksum, parsing it into header values
        and data...).
        Then check the protocol state, do appropriate state-based processing
        (e.g. a FIN is not an acceptable segment in ACCEPTING state, whereas a
        SYN is).
        Finally, do post-processing that is common to all states.

        You could e.g. implement the state-specific processing in a helper
        function per state, and simply call the appropriate helper function
        based on which state you are in.
        In that case, it will be very helpful to split your processing into
        smaller helper functions, that you can combine as needed into a larger
        function for each state.
        """
        logger.debug("lossy_layer_segment_received called")

        result = self._common_segment_processing(segment)
        if result is None: 
            return
        
        seqnum, acknum, syn, ack, fin, window, length, data = result
        
        if self._state == BTCPStates.SYN_SENT:
            self._syn_sent_segment_received(seqnum, acknum, syn, ack, fin, window, length, data)
        elif self._state == BTCPStates.ESTABLISHED:
            self._established_segment_received(seqnum, acknum, syn, ack, fin, window, length, data)
        elif self._state == BTCPStates.FIN_SENT:
            self._fin_sent_segment_received(seqnum, acknum, syn, ack, fin, window, length, data)
        elif self._state == BTCPStates.CLOSING:
            self._closing_segment_received(seqnum, acknum, syn, ack, fin, window, length, data)
        else:
            logger.debug(f"Ignoring segment received by client in state {self._state.name}")

        if ack:
            logger.info("Acknowledged lossy layer segment received client side")

    def _common_segment_processing(self, segment):
        if len(segment) != SEGMENT_SIZE:
            logger.warning("Received Segment with incorrect size")
            return None
        
        if not self.verify_checksum(segment):
            logger.warning("Checksum verification failed")
            return None

        try:
            seqnum, acknum, syn, ack, fin, window, length, _ = self.unpack_segment_header(segment[:HEADER_SIZE])
        except Exception as e:
            logger.error(f"Failed to unpack header: {e}")
            return None

        data = segment[HEADER_SIZE:HEADER_SIZE + length] if length > 0 else b''
        
        return seqnum, acknum, syn, ack, fin, window, length, data
    

    # I got this from the Correct FSMs found in FSMs-studentversion.pdf
    def _syn_sent_segment_received(self, seqnum, acknum, syn, ack, fin, window, length, data):
        if syn and ack:
            expected_ack = (self._seqnum + 1) % 65536
            if acknum == expected_ack:
                logger.info("Received SYN|ACK from server")
        
                self._state = BTCPStates.ESTABLISHED
                self._send_window = window
                self._seqnum = expected_ack
                self._send_base = expected_ack

                self._next_seqnum = expected_ack                
                self._send_ack(acknum=seqnum+1)
                logger.info("Handshake completed?")
                return True

        logger.info("Ignored unexpected segment in SYN_SENT")
        return False

    def _established_segment_received(self, seqnum, acknum, syn, ack, fin, window, length, data):
        if fin:
            logger.info("Received FIN from server so closing")
            self._state = BTCPStates.CLOSING
            self._send_fin_ack()
            return True
        if ack:
            self._process_acknowledgement(acknum, window)
            return True
        
        logger.debug("Ignored non-ACK/non-FIN segment in ESTABLISHED")
        return False 

    def _fin_sent_segment_received(self, seqnum, acknum, syn, ack, fin, window, length, data):
        if fin and ack:
            if acknum == (self._seqnum + 1) % 65536:
                logger.info("Received FIN|ACK from server so connection closing")
                self._state = BTCPStates.CLOSING
                self._send_ack(acknum=acknum)
                return True
        logger.debug("Ignored unexpected segment in FIN_SENT")
        return False

    def _closing_segment_received(self, seqnum, acknum, syn, ack, fin, window, length, data):
        if ack:
            logger.info("Received final ACK in CLOSING so connection terminated")
            self._state = BTCPStates.CLOSED
            return True
        
        logger.debug("Ignored segment in CLOSING")
        return False
    


    def _send_ack(self, acknum, window=None):
        """Helper function to send a pure ACK segment"""
        if window is None:
            window = self._window
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

    def _send_fin_ack(self):
        """Helper function to send a FIN|ACK segment"""
        header = self.build_segment_header(
            seqnum=self._seqnum,
            acknum=0,
            syn_set=False,
            ack_set=True,
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
            ack_set=True,
            fin_set=True,
            window=self._send_window,
            length=0,
            checksum=checksum
        )
        segment = header + b'\x00' * PAYLOAD_SIZE
        self._lossy_layer.send_segment(segment)
        logger.info("Sent FIN|ACK")

    def _process_acknowledgement(self, acknum, window):
        logger.debug(f"Processing ACK for acknum={acknum}, advertised window={window}")
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


    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received.

        For example, checking for timeouts on acknowledgement of previously
        sent segments -- to trigger retransmission -- should work even if no
        segments are being received. Although you can't count these ticks
        themselves for the timeout, you can trigger the check from here.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called")
        # raise_NotImplementedError("Only rudimentary implementation of lossy_layer_tick present. Read the comments & code of client_socket.py, then remove the NotImplementedError.")

        # Actually send all chunks available for sending.
        # Relies on an eventual exception to break from the loop when no data
        # is available.
        # You should eventually for flow cotrol  be checking whether there's space in the window as well,
        # for reliable data transfer be storing the segments for retransmission somewhere.
        current_time = time.monotonic_ns()

        self._check_retransmissions(current_time)
        self._send_pending_data()
    
        # try:
        #     while True:
        #         logger.debug("Getting chunk from buffer.")
        #         chunk = self._sendbuf.get_nowait()
        #         datalen = len(chunk)
        #         logger.debug("Got chunk with length %i:", datalen)
        #         logger.debug(chunk)
        #         if datalen < PAYLOAD_SIZE:
        #             logger.debug("Padding chunk to full size")
        #             chunk = chunk + b'\x00' * (PAYLOAD_SIZE - datalen)
        #         logger.debug("Building segment from chunk.")
        #         segment = (self.build_segment_header(self._seqnum, 0, length=datalen)
        #                    + chunk)
        #         logger.info("Sending segment.")
        #         self._lossy_layer.send_segment(segment)
        # except queue.Empty:
        #     logger.info("No (more) data was available for sending right now.")

    def _check_retransmissions(self, current_time):
        timeout_ns = self.timeout_nanosecs

        for seqnum, (segment, send_time) in list(self._unacked.items()):
            if current_time - send_time > timeout_ns:
                logger.warning(f"Timeout on segment seq={seqnum} - retransmitting")
                self._lossy_layer.send_segment(segment)

                self._unacked[seqnum] = (segment, current_time)

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

    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### connect, shutdown (disconnect), send data, etc. Conceptually, this  ###
    ### happens in "the application thread".                                ###
    ###                                                                     ###
    ### Note that because this is the client socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no recv() method available to the applications. You should still    ###
    ### be able to receive segments on the lossy layer, however, because    ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above (in lossy_layer_...)                                          ###
    ###########################################################################

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