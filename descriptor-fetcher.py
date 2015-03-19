"""
Retrieve descriptors from popular hidden services. (every 10 min).
"""

import sys
import time
import argparse
import struct
import hashlib
import datetime
import os
import logging

from sqlalchemy import create_engine
from sqlalchemy.orm import scoped_session, sessionmaker
from sqlalchemy.ext.declarative import declarative_base
from sqlalchemy import Column, Integer, String, DateTime

import stem
import stem.control
import schedule

handler = logging.StreamHandler()
handler.setFormatter(logging.Formatter(fmt="%(asctime)s [%(levelname)s]: "
                                           "%(message)s"))

logger = logging.getLogger("onion-load-balancer")
logger.addHandler(handler)
logger.setLevel(logging.DEBUG)

engine = create_engine('sqlite:///database.db', convert_unicode=True)
db_session = scoped_session(sessionmaker(autocommit=False,
                                         autoflush=False,
                                         bind=engine))
Base = declarative_base()
Base.query = db_session.query_property()


class HSDescriptor(Base):
    """
    Store information about the descriptors uploaded to the HSDir's
    """
    __tablename__ = 'descriptorrequests'
    id = Column(Integer, primary_key=True)
    action = Column(String(20))
    address = Column(String(20))
    descriptor_id = Column(String(40))
    hsdir_fingerprint = Column(String(30))
    reason = Column(String(20))  # Reason for lookup failure
    descriptor_hash = Column(String(80))
    timestamp = Column(DateTime, default=datetime.datetime.utcnow)


# Descriptor Calculations
def get_time_period(time, permanent_id):
    """
    time-period = (current-time + permanent-id-byte * 86400 / 256) / 86400
    """
    permanent_id_byte = int(struct.unpack('B', permanent_id[0])[0])
    return (time + permanent_id_byte * 86400 / 256) / 86400


def calc_secret_id_part(time_period, replica, descriptor_cookie=None):
    """
    secret-id-part = H(time-period | descriptor-cookie | replica)
    """
    secret_id_part = hashlib.sha1()
    secret_id_part.update(struct.pack('>I', time_period)[:4])
    if descriptor_cookie:
        secret_id_part.update(descriptor_cookie)
    secret_id_part.update('{0:02X}'.format(replica).decode('hex'))
    return secret_id_part.digest()


def calc_descriptor_id(permanent_id, replica, timestamp=None,
                       descriptor_cookie=None):
    if not timestamp:
        timestamp = int(time.time())
    time_period = get_time_period(timestamp, permanent_id)
    secret_id_part = calc_secret_id_part(time_period, replica,
                                         descriptor_cookie)
    descriptor_id = hashlib.sha1(permanent_id + secret_id_part).digest()
    return descriptor_id


# Descriptor Fetching
def hs_desc_handler(event):
    """
    Handle the event received when Tor emits a HS descriptor event
    Store request information in DB and store unique descriptors to disk,
    """
    # Handle the event received when Tor gets a HS descriptor
    if event.type == "HS_DESC":
        # Create database object
        hs_desc_item = HSDescriptor(
            action=event.action,
            address=event.address,
            descriptor_id=event.descriptor_id,
            hsdir_fingerprint=event.directory_fingerprint,
            reason=event.reason,
        )
        db_session.add(hs_desc_item)

        if event.reason:
            print(event.directory_fingerprint, event.address,
                  event.reason)
            logger.info("Descriptor fetching from {} for HS {} failed "
                        "with error: {}".format(event.directory_fingerprint,
                                                event.address, event.reason))

    if event.type == "HS_DESC_CONTENT":
        # Save the descriptor content to disk
        descriptor_text = str(event.descriptor).encode('utf-8')

        # Make sure the descriptor is not empty
        if len(descriptor_text) < 5:
            logger.debug("Empty descriptor received for %s" % event.address)
            return

        descriptor_hash = hashlib.sha1(descriptor_text).hexdigest()
        descriptor_path = os.path.join("descriptors", descriptor_hash)

        if not os.path.isfile(descriptor_path):
            with open(descriptor_path, 'wb') as descriptor_file:
                descriptor_file.write(descriptor_text)
            logger.info("Storing new descriptor for HS %s" % event.address)
        else:
            logger.info("Received matching descriptor for HS %s" %
                        event.address)

        # Save the data about returned descriptor to DB
        hs_desc_content_event = HSDescriptor(
            action=event.type,
            address=event.address,
            descriptor_id=event.descriptor_id,
            hsdir_fingerprint=event.directory_fingerprint,
            descriptor_hash=descriptor_hash
        )
        db_session.add(hs_desc_content_event)

    db_session.commit()
    return


def request_descriptor(controller, onion_address):
    logger.info("Sending HS descriptor fetch for %s.onion" % onion_address)
    response = controller.msg("HSFETCH %s" % (onion_address))
    if not response.is_ok():
        if response.code == "552":
            raise stem.InvalidRequest(response.code, response.message)
        else:
            raise stem.ProtocolError("HSFETCH returned unexpected response "
                                     "code: %s" % response.code)


def descriptor_fetch(controller, onion_list):
    # Before beginning fetches, send NEWNYM to clear desc cache
    controller.signal(stem.control.Signal.NEWNYM)
    time.sleep(5)  # Wait for Tor to be ready

    for onion_address in onion_list:
        request_descriptor(controller, onion_address)
        time.sleep(5)  # Wait a bit between descriptor lookups


# def request_descriptor_from_hsdir(controller, descriptor_id, hsdir_fpr):
#     response = controller.msg("HSFETCH v2-%s SERVER=%s" % (descriptor_id,
#                               hsdir_fpr))

#     if not response.is_ok():
#         if response.code == "552":
#             raise stem.InvalidRequest(response.code, response.message)
#         else:
#             raise stem.ProtocolError("HSFETCH returned unexpected response "
#                                      "code: %s" % response.code)


def parse_cmd_args():
    """
    Parses and returns command line arguments.
    """

    parser = argparse.ArgumentParser(
        description="%s fetch Tor hidden service descriptors" % sys.argv[0])

    parser.add_argument("-i", "--ip", type=str, default="127.0.0.1",
                        help="Tor controller IP address")

    parser.add_argument("-p", "--port", type=int, default=9051,
                        help="Tor controller port")

    parser.add_argument("--onion", type=str, default=None,
                        help="Address of hidden service to fetch.")

    parser.add_argument("--onion-list", type=argparse.FileType("r"),
                        default=None,  help="List of HS addresses to fetch")

    return parser.parse_args()


def main():

    args = parse_cmd_args()

    if args.onion_list:
        onion_list = args.onion_list.read().strip().split('\n')
    elif args.onion:
        onion_list = [args.onion]
    else:
        logger.error("No onion addresses were specified")
        sys.exit(1)

    os.makedirs("descriptors", exist_ok=True)

    with stem.control.Controller.from_port(port=args.port) \
            as controller:
        # Create a connection to the Tor control port
        try:
            controller.authenticate()
        except stem.connection.AuthenticationFailure as exc:
            logger.error("Unable to authenticate to Tor control port: %s" %
                         exc)
            sys.exit(1)
        else:
            controller.set_caching(False)
            logger.debug("Successfully connected to the Tor control port")

        # Add event listeners for HS_DESC and HS_DESC_CONTENT
        controller.add_event_listener(hs_desc_handler,
                                      stem.control.EventType.HS_DESC)
        controller.add_event_listener(hs_desc_handler,
                                      stem.control.EventType.HS_DESC_CONTENT)

        # Add scheduled descriptor polling
        schedule.every(10).minutes.do(descriptor_fetch, controller, onion_list)

        # Run first fetch on startup
        descriptor_fetch(controller, onion_list)

        # Main loop to poll for HS descriptors
        try:
            while True:
                schedule.run_pending()
                time.sleep(1)
        except KeyboardInterrupt:
            logger.info("Stopping descriptor fetching")

    sys.exit(0)

if __name__ == '__main__':
    Base.metadata.create_all(bind=engine)
    main()
