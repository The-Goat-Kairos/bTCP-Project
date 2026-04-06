#!/usr/bin/env python3

import argparse
import time
import logging

# Import the socket
from btcp.socket import Socket

"""This exposes a constant bytes object called TEST_BYTES_85MIB which, as the
name suggests, is a little over 85 MiB in size.
You can also use large_input.py as-is for file transfer.
"""
from large_input import TEST_BYTES_85MIB


logger = logging.getLogger(__name__)


def btcp_file_transfer_client():
    """bTCP file transfer client using the merged Socket class."""
    parser = argparse.ArgumentParser()
    parser.add_argument("-w", "--window",
                        help="Define bTCP window size",
                        type=int, default=100)
    parser.add_argument("-t", "--timeout",
                        help="Define bTCP timeout in seconds",
                        type=int, default=10)
    parser.add_argument("-i", "--input",
                        help="File to send",
                        default="large_input.py")
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

    # Create the merged bTCP socket
    logger.info("Creating merged bTCP socket (client role)")
    s = Socket(args.window, args.timeout)

    # Connect to the server
    logger.info("Connecting to server...")
    s.connect()
    logger.info("Connection established")

    # Send the file
    logger.info(f"Opening input file: {args.input}")
    with open(args.input, 'rb') as infile:
        chunksize = 1_024_000
        data = bytearray(infile.read(chunksize))

        while data:
            logger.info(f"Queueing {len(data)} bytes for sending")
            while data:
                sent_bytes = s.send(data)
                del data[:sent_bytes]
                time.sleep(0.005)   # small backoff to let network thread process

            # Read next chunk
            data = bytearray(infile.read(chunksize))

        logger.info("All data has been queued for transmission")

    # Gracefully shutdown the connection
    logger.info("Initiating shutdown")
    s.shutdown()

    # Clean up
    logger.info("Closing socket")
    s.close()

    logger.info("Client finished successfully")


if __name__ == "__main__":
    logger = logging.getLogger("client_app.py")
    btcp_file_transfer_client()