"""
CPSC 5520, Seattle University
:Authors: Benjamin Philipose
:Version: f24-01
"""

from array import array
from datetime import datetime
import ipaddress

def deserialize_price(b: bytes) -> float:
    """
    Deserialize a float from a byte string.

    Args:
        b (bytes): A byte string containing a serialized float in IEEE 754 format.

    Returns:
        float: The deserialized float price value.
    """
    a = array('f') #create an array to hold floats
    a.frombytes(b)
    return a[0]  #return the first element, which is the deserialized float

def serialize_address(address: (str, int)) -> bytes:
    """
    Serialize an IP address and port number into a 6-byte string.

    Args:
        address (str, int): A tuple containing an IP address and port number.

    Returns:
        bytes: The serialized byte string of the IP address and port number.
    """
    host, port = address
    if host == 'localhost':
        host = '127.0.0.1'
    ip = ipaddress.ip_address(host).packed  # 4 bytes for the IP address
    p = array('H', [port])  # 2 bytes for the port number
    p.byteswap()  # convert to big-endian for network format
    return ip + p.tobytes()

MICROS_PER_SECOND = 1_000_000

def deserialize_utcdatetime(b: bytes) -> datetime:
    """
    Deserialize a datetime object from a 8-byte string.

    Args:
        b (bytes): A byte string containing a serialized datetime in microseconds since epoch.

    Returns:
        datetime: The deserialized datetime object.
    """
    a = array('Q') 
    a.frombytes(b)
    #convert from big-endian to native format
    a.byteswap()
    micros_since_epoch = a[0]  #extract the number of microseconds
    seconds, micros = divmod(micros_since_epoch, MICROS_PER_SECOND)
    return datetime.utcfromtimestamp(seconds + micros / MICROS_PER_SECOND)


def deserialize_message(message: bytes) -> list:
    """
    Deserialize a byte string containing 32-byte forex quotes into a list of quotes.

    Args:
        message (bytes): A byte string containing serialized forex quotes.

    Returns:
        list: A list of dictionaries containing the parsed forex quotes.
    """
    quotes = []
    for i in range(0, len(message), 32): #Extract each 32-byte quote
        quote = message[i:i+32]
        currency1 = quote[0:3].decode('ascii')  #0-3 bytes are currency1
        currency2 = quote[3:6].decode('ascii')  #3-6 bytes are currency2
        rate = deserialize_price(quote[6:10])   #6-10 bytes are the exchange rate
        timestamp = deserialize_utcdatetime(quote[10:18])  #10-18 bytes are the timestamp
        # Add the parsed quote to the list
        quotes.append({
            'currency1': currency1,
            'currency2': currency2,
            'rate': rate,
            'timestamp': timestamp
        })
    return quotes
