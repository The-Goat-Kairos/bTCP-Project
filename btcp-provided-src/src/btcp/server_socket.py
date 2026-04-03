from btcp.btcp_socket import BTCPSocket, BTCPStates, BTCPSignals, raise_NotImplementedError
from btcp.lossy_layer import LossyLayer
from btcp.constants import *

import queue
import time
import struct
import logging
import random


logger = logging.getLogger(__name__)


class BTCPServerSocket(BTCPSocket):
    """bTCP server socket
    A server application makes use of the services provided by bTCP by calling
    accept, recv, and close.

    You're implementing the transport layer, exposing it to the application
    layer as a (variation on) socket API. Do note, however, that this socket
    as presented is *always* in "listening" state, and handles the client's
    connection in the same socket. You do not have to implement a separate
    listen socket. If you get everything working, you may do so for some extra
    credit.

    To implement the transport layer, you also need to interface with the
    network (lossy) layer. This happens by both calling into it
    (LossyLayer.send_segment) and providing callbacks for it
    (BTCPServerSocket.lossy_layer_segment_received, lossy_layer_tick).

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
        """Constructor for the bTCP server socket. Allocates local resources
        and starts an instance of the Lossy Layer.
        """

        logger.debug("__init__() called.")
        self._expected_seqnum = None
        self._reorder_buffer = {}
        super().__init__(window, timeout, isn)
        self._lossy_layer = LossyLayer(self, SERVER_IP, SERVER_PORT, CLIENT_IP, CLIENT_PORT)

        # The data buffer used by lossy_layer_segment_received to move data
        # from the network thread into the application thread. Bounded in size.
        # If data overflows the buffer it will get lost -- that's what window
        # size negotiation should solve.
        # For this rudimentary implementation, we simply hope receive manages
        # to be faster than send.
        self._recvbuf = queue.Queue(maxsize=1000)
        logger.info("Socket initialized with recvbuf size 1000")

        self._remote_isn = 0
        self._next_seqnum = 0
        self._receive_window = window
        # Make sure the example timer exists from the start.
        self._lossy_layer.start_network_thread()


    ###########################################################################
    ### The following section is the interface between the transport layer  ###
    ### and the lossy (network) layer. When a segment arrives, the lossy    ###
    ### layer will call the lossy_layer_segment_received method "from the   ###
    ### network thread". In that method you should handle the checking of   ###
    ### the segment, and take other actions that should be taken upon its   ###
    ### arrival, like acknowledging the segment and making the data         ###
    ### available for the application thread that calls to recv can return  ###
    ### the data.                                                           ###
    ###                                                                     ###
    ### Of course you can implement this using any helper methods you want  ###
    ### to add.                                                             ###
    ###                                                                     ###
    ### Since the implementation is inherently multi-threaded, you should   ###
    ### use a Queue, not a List, to transfer the data to the application    ###
    ### layer thread: Queues are inherently threadsafe, Lists are not.      ###
    ###########################################################################

    def lossy_layer_segment_received(self, segment):
        """Called by the lossy layer whenever a segment arrives.

        Things you should expect to handle here (or in helper methods called
        from here):
            - checksum verification (and deciding what to do if it fails)
            - receiving syn and client's ack during handshake
            - receiving segments and sending acknowledgements for them,
              making data from those segments available to application layer
            - receiving fin and client's ack during termination
            - any other handling of the header received from the client

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
            return # just bail

        # seqnum, acknum, syn, ack, fin, window, length, data = result

        match self._state:
            case BTCPStates.CLOSED:
                self._closed_segment_received(result)
            case BTCPStates.CLOSING:
                self._closing_segment_received(result)
            case BTCPStates.SYN_RCVD:
                self._syn_rcvd_segment_received(result)
            case BTCPStates.ESTABLISHED:
                self._established_segment_received(result)
            case _:
                logger.debug(f"Ignoring segment received by server in state {self._state.name}")

        # self._expire_timers()

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
        
        print("What the server is receiving in BTCPServerSocket._common_segment_processing:")
        print(seqnum, acknum, syn, ack, fin, window, length, data)
        return seqnum, acknum, syn, ack, fin, window, length, data

    def _closed_segment_received(self, result):
        """Helper method handling received segment in CLOSED state"""
        seqnum, acknum, syn, ack, fin, window, length, data = result
        logger.debug("_closed_segment_received called")
        logger.debug("syn %i, ack %i, fin %i", syn, ack, fin)
        print("HELPPPPPPPPPPPP: ", syn, ack, fin)
        if syn and not ack and not fin:
            logger.info(f"Received SYN from client (seq={seqnum})")
            self._state = BTCPStates.SYN_RCVD
            self._remote_isn = seqnum                           # store client's ISN (x)
            self._expected_seqnum = (seqnum + 1) % 65536
            self._send_syn_ack(acknum=seqnum + 1)     # ack = x + 1
            logger.debug("Closed segment received and sent SYN|ACK")
        else:
            logger.debug("Ignored non-SYN segment in CLOSED state")


    def _closing_segment_received(self, result):
        """Helper method handling received segment in CLOSING state"""
        seqnum, acknum, syn, ack, fin, window, length, data = result
        if ack:
            logger.info("Received final ACK so terminating")
            self._state = BTCPStates.CLOSED
            return True
        
        logger.debug("Ignored segment received by server in CLOSING")
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
                return True
        
        logger.debug("Ignored unexpected segment received by SERVER in SYN_RCVD")
        return False


    def _established_segment_received(self, result):
        """Helper method handling received segment in ESTABLISHED state"""
        seqnum, acknum, syn, ack, fin, window, length, data = result
        
        # Update receive window from client's advertisement
        if window > 0:
            self._receive_window = window
        
        if fin:
            logger.info("Received FIN from client")
            self._state = BTCPStates.CLOSING
            self._send_fin_ack()
            return True
                
        if length > 0:
            # Check if this is the expected next segment
            if seqnum == self._expected_seqnum:
                # Deliver data in order
                self._deliver_data(data)
                self._expected_seqnum = (self._expected_seqnum + 1) % 65536
                
                # Check for buffered segments that are now in order
                while self._expected_seqnum in self._reorder_buffer:
                    buffered_data = self._reorder_buffer.pop(self._expected_seqnum)
                    self._deliver_data(buffered_data)
                    self._expected_seqnum = (self._expected_seqnum + 1) % 65536
                
                # Send ACK for the received data
                self._send_ack(acknum=self._expected_seqnum, window=self._receive_window)
                
            elif (seqnum - self._expected_seqnum) % 65536 < 32768:
                # Out-of-order but within window - buffer it
                if seqnum not in self._reorder_buffer:
                    self._reorder_buffer[seqnum] = data
                    logger.debug(f"Buffered out-of-order segment seq={seqnum}")
                    # Send duplicate ACK for expected sequence number
                    self._send_ack(acknum=self._expected_seqnum, window=self._receive_window)
                else:
                    logger.debug(f"Duplicate buffered segment seq={seqnum}")
            else:
                # Old packet - ignore but send ACK anyway
                logger.debug(f"Ignoring old segment seq={seqnum}")
                self._send_ack(acknum=self._expected_seqnum, window=self._receive_window)
            
            return True
        
        if ack:
            # Handle ACKs if needed
            pass
        
        logger.debug("Ignored segment received by server in ESTABLISHED")
        return False


    def _deliver_data(self, data):
        try:
            self._recvbuf.put_nowait(data)
            logger.debug(f"Delivered {len(data)} bytes to recv buffer")
        except queue.Full:
            logger.warning("Receive buffer full so dropping data")



    def lossy_layer_tick(self):
        """Called by the lossy layer whenever no segment has arrived for
        TIMER_TICK milliseconds. Defaults to 100ms, can be set in constants.py.

        NOTE: Will NOT be called if segments are arriving; do not rely on
        simply counting calls to this method for an accurate timeout. If 10
        segments arrive, each 99 ms apart, this method will NOT be called for
        over a second!

        The primary use for this method is to be able to do things in the
        "network thread" even while no segments are arriving -- which would
        otherwise trigger a call to lossy_layer_segment_received. On the server
        side, you may find you have no actual need for this method. Or maybe
        you do. See if it suits your implementation.

        You will probably see some code duplication of code that doesn't handle
        the incoming segment among lossy_layer_segment_received and
        lossy_layer_tick. That kind of duplicated code would be a good
        candidate to put in a helper method which can be called from either
        lossy_layer_segment_received or lossy_layer_tick.
        """
        logger.debug("lossy_layer_tick called")
        # self._start_example_timer()
        # self._expire_timers()
        # raise_NotImplementedError("No implementation of lossy_layer_tick present. Read the comments & code of server_socket.py.")


    # The following two functions show you how you could implement a (fairly
    # inaccurate) but easy-to-use timer.
    # You *do* have to call _expire_timers() from *both* lossy_layer_tick
    # and lossy_layer_segment_received, for reasons explained in
    # lossy_layer_tick.
    # def _start_example_timer(self):
    #     if not self._example_timer:
    #         logger.debug("Starting example timer.")
    #         # Time in *nano*seconds, not milli- or microseconds.
    #         # Using a monotonic clock ensures independence of weird stuff
    #         # like leap seconds and timezone changes.
    #         self._example_timer = time.monotonic_ns()
    #     else:
    #         logger.debug("Example timer already running.")


    # def _expire_timers(self):
    #     curtime = time.monotonic_ns()
    #     if not self._example_timer:
    #         logger.debug("Example timer not running.")
    #     elif curtime - self._example_timer > self.timeout_nanosecs:
    #         logger.debug("Example timer elapsed.")
    #         self._example_timer = None
    #     else:
    #         logger.debug("Example timer not yet elapsed.")

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

    def _send_syn_ack(self, acknum):
        """Helper function to send a SYN|ACK segment"""
        header = self.build_segment_header(
            seqnum=self._seqnum,
            acknum=acknum,
            syn_set=True,
            ack_set=True,
            fin_set=False,
            window=self._receive_window,
            length=0,
            checksum=0
        )

        segment = header + b'\x00' * PAYLOAD_SIZE
        checksum = self.in_cksum(segment)

        header = self.build_segment_header(
            seqnum=self._seqnum,
            acknum=acknum,
            syn_set=True,
            ack_set=True,
            fin_set=False,
            window=self._receive_window,
            length=0,
            checksum=checksum
        )

        segment = header + b'\x00' * PAYLOAD_SIZE
        self._lossy_layer.send_segment(segment)
        logger.info(f"Sent SYN|ACK (seq={self._seqnum}, ack={acknum})")

    def _send_fin_ack(self):
        """Helper function to send a FIN|ACK segment"""
        header = self.build_segment_header(
            seqnum=self._seqnum,
            acknum=0,
            syn_set=False,
            ack_set=True,
            fin_set=True,
            window=self._receive_window,
            length=0
        )
        segment = header + b'\x00' * PAYLOAD_SIZE
        checksum = self.in_cksum(segment)
        header = self.build_segment_header(
            seqnum=self._seqnum,
            acknum=0,
            syn_set=False,
            ack_set=True,
            fin_set=True,
            window=self._receive_window,
            length=0,
            checksum=checksum
        )
        segment = header + b'\x00' * PAYLOAD_SIZE
        self._lossy_layer.send_segment(segment)
        logger.info("Sent FIN|ACK")


    ###########################################################################
    ### You're also building the socket API for the applications to use.    ###
    ### The following section is the interface between the application      ###
    ### layer and the transport layer. Applications call these methods to   ###
    ### accept connections, receive data, etc. Conceptually, this happens   ###
    ### in "the application thread".                                        ###
    ###                                                                     ###
    ### Note that because this is the server socket, and our (initial)      ###
    ### implementation of bTCP is one-way reliable data transfer, there is  ###
    ### no send() method available to the applications. You should still    ###
    ### be able to send segments on the lossy layer, however, because       ###
    ### of acknowledgements and synchronization. You should implement that  ###
    ### above.                                                              ###
    ###########################################################################

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
        logger.debug("accept called")

        start_time = time.monotonic()

        while self._state != BTCPStates.ESTABLISHED:
            if time.monotonic() - start_time > self.timeout_secs:
                logger.error("Accept timeout reached")
                return
            time.sleep(0.05)

        logger.info("Connection accepted")


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
        # raise_NotImplementedError("Only rudimentary implementation of recv present. Read the comments & code of server_socket.py, then remove the NotImplementedError.")

        # Rudimentary example implementation:
        # Empty the queue in a loop, reading into a larger bytearray object.
        # Once empty, return the data as bytes.
        # If no data is received for the given timeout, a disconnect is assumed.
        # At that point recv returns no data and thereby signals disconnect
        # to the server application.
        # Proper handling should use the bTCP state machine to check that the
        # client has disconnected when a timeout happens, and keep blocking
        # until data has actually been received if it's still possible for
        # data to appear.

        # try:
        #     # Wait until one segment becomes available in the buffer, or
        #     # timeout signalling disconnect.
        #     logger.info("Blocking get for first chunk of data.")
        #     data.extend(self._recvbuf.get(block=True, timeout=self.timeout_secs)) 
        #     logger.debug("First chunk of data retrieved.")
        #     logger.debug("Looping over rest of queue.")
        #     while True:
        #         # Empty the rest of the buffer, until queue.Empty exception
        #         # exits the loop. If that happens, data contains received
        #         # segments so that will *not* signal disconnect.
        #         data.extend(self._recvbuf.get_nowait())
        #         logger.debug("Additional chunk of data retrieved.")
        # except queue.Empty:
        #     logger.debug("Queue emptied or timeout reached")
        #     pass # (Not break: the exception itself has exited the loop)
        # logger.info(data)
        # if not data:
        #     logger.info(f"No data received for {self.timeout_secs} seconds.")
        #     logger.info("Returning empty bytes to caller, signalling disconnect.")
        # return bytes(data)


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