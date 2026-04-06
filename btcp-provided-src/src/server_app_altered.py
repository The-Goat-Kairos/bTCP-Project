#!/usr/bin/env python3

import argparse
import logging

# Import the socket
from btcp.socket import Socket

"""This exposes a constant bytes object called TEST_BYTES_85MIB.
You can also use large_input.py as-is for file transfer.
"""
from large_input import TEST_BYTES_85MIB


logger = logging.getLogger(__name__)


def btcp_file_transfer_server():
    """bTCP file transfer server using the merged Socket class."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--window",
                        help="Define bTCP window size",
                        type=int, default=100)
    parser.add_argument("-t", "--timeout",
                        help="Define bTCP timeout in seconds",
                        type=int, default=10)
    parser.add_argument("-o", "--output",
                        help="Where to store the received file",
                        default="output.file")
    parser.add_argument("-l", "--loglevel",
                        choices=["DEBUG", "INFO", "WARNING",
                                 "ERROR", "CRITICAL"],
                        help="Log level for the python built-in logging module.",
                        default="DEBUG")
    parser.add_argument("-s", "--suppress-not-implemented-errors",
                        action="store_true",
                        help="Suppresses initial NotImplementedErrors")
    args = parser.parse_args()

    logging.basicConfig(level=getattr(logging, args.loglevel.upper()),
                        format="%(asctime)s:%(name)s:%(levelname)s:%(message)s")
    logger.info("Logger initialized")

    if args.suppress_not_implemented_errors:
        import btcp.btcp_socket
        btcp.btcp_socket.__suppress_nie = True

    # Create the merged bTCP socket
    logger.info("Creating merged bTCP socket (server role)")
    s = Socket(args.window, args.timeout)

    # Accept incoming connection
    logger.info("Waiting for client connection...")
    s.accept()
    logger.info("Connection accepted")

    # Receive the file
    logger.info(f"Opening output file: {args.output}")
    with open(args.output, 'wb') as outfile:
        logger.info("Receiving first chunk...")
        recvdata = s.recv()

        while recvdata:
            logger.info(f"Received {len(recvdata)} bytes - writing to file")
            outfile.write(recvdata)
            recvdata = s.recv()

        # Empty bytes from recv() signals disconnection
        logger.info("All data received - connection closed by client")

    # Clean up
    logger.info("Closing socket")
    s.close()

    logger.info("Server finished successfully")


if __name__ == "__main__":
    logger = logging.getLogger("server_app.py")
    btcp_file_transfer_server()