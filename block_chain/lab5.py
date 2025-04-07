"""
CPSC 5520, Seattle University
:Authors: Benjamin Philipose
:Version: f24-01
"""
import socket
import hashlib 
import time


# Constants
MAGIC_BYTES = bytearray.fromhex("f9beb4d9")  #magic bytes
HDR_SZ = 24  #bitcoin header size
PORT = 8333  #Bitcoin port
VERSION = 70015  #Protocal version
BHOST = '5.14.1.135'
BPORT = 8333
SU_ID = 4140754
TARGET_BLOCK = SU_ID % 10000

def compactsize_t(n):
    if n < 252:
        return uint8_t(n)
    if n < 0xffff:
        return uint8_t(0xfd) + uint16_t(n)
    if n < 0xffffffff:
        return uint8_t(0xfe) + uint32_t(n)
    return uint8_t(0xff) + uint64_t(n)

def unmarshal_compactsize(b):
    key = b[0]
    if key == 0xff:
        return b[0:9], unmarshal_uint(b[1:9])
    if key == 0xfe:
        return b[0:5], unmarshal_uint(b[1:5])
    if key == 0xfd:
        return b[0:3], unmarshal_uint(b[1:3])
    return b[0:1], unmarshal_uint(b[0:1])

def bool_t(flag):
    return uint8_t(1 if flag else 0)

def ipv6_from_ipv4(ipv4_str):
    pchIPv4 = bytearray([0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0xff, 0xff])
    return pchIPv4 + bytearray((int(x) for x in ipv4_str.split('.')))

def ipv6_to_ipv4(ipv6):
    return '.'.join([str(b) for b in ipv6[12:]])

def uint8_t(n):
    return int(n).to_bytes(1, byteorder='little', signed=False)

def uint16_t(n, byteorder='little'):
    return int(n).to_bytes(2, byteorder=byteorder, signed=False)

def int32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=True)

def uint32_t(n):
    return int(n).to_bytes(4, byteorder='little', signed=False)

def int64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=True)

def uint64_t(n):
    return int(n).to_bytes(8, byteorder='little', signed=False)

def unmarshal_int(b):
    return int.from_bytes(b, byteorder='little', signed=True)

def unmarshal_uint(b, byteorder='little'):
    return int.from_bytes(b, byteorder=byteorder, signed=False)

def print_message(msg, text=None):
    """
    Report the contents of the given bitcoin message
    :param msg: bitcoin message including header
    :return: message type
    """
    print('\n{}MESSAGE'.format('' if text is None else (text + ' ')))
    print('({}) {}'.format(len(msg), msg[:60].hex() + ('' if len(msg) < 60 else '...')))
    payload = msg[HDR_SZ:]
    command = print_header(msg[:HDR_SZ], checksum(payload))
    if command == 'version':
        print_version_msg(payload)
    # FIXME print out the payloads of other types of messages, too
    return command

def print_version_msg(b):
    """
    Report the contents of the given bitcoin version message (sans the header)
    :param payload: version message contents
    """
    # pull out fields
    version, my_services, epoch_time, your_services = b[:4], b[4:12], b[12:20], b[20:28]
    rec_host, rec_port, my_services2, my_host, my_port = b[28:44], b[44:46], b[46:54], b[54:70], b[70:72]
    nonce = b[72:80]
    user_agent_size, uasz = unmarshal_compactsize(b[80:])
    i = 80 + len(user_agent_size)
    user_agent = b[i:i + uasz]
    i += uasz
    start_height, relay = b[i:i + 4], b[i + 4:i + 5]
    extra = b[i + 5:]

    # print report
    prefix = '  '
    print(prefix + 'VERSION')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} version {}'.format(prefix, version.hex(), unmarshal_int(version)))
    print('{}{:32} my services'.format(prefix, my_services.hex()))
    time_str = time.strftime("%a, %d %b %Y %H:%M:%S GMT", time.gmtime(unmarshal_int(epoch_time)))
    print('{}{:32} epoch time {}'.format(prefix, epoch_time.hex(), time_str))
    print('{}{:32} your services'.format(prefix, your_services.hex()))
    print('{}{:32} your host {}'.format(prefix, rec_host.hex(), ipv6_to_ipv4(rec_host)))
    print('{}{:32} your port {}'.format(prefix, rec_port.hex(), unmarshal_uint(rec_port, 'big')))
    print('{}{:32} my services (again)'.format(prefix, my_services2.hex()))
    print('{}{:32} my host {}'.format(prefix, my_host.hex(), ipv6_to_ipv4(my_host)))
    print('{}{:32} my port {}'.format(prefix, my_port.hex(), unmarshal_uint(my_port, 'big')))
    print('{}{:32} nonce'.format(prefix, nonce.hex()))
    print('{}{:32} user agent size {}'.format(prefix, user_agent_size.hex(), uasz))
    print('{}{:32} user agent \'{}\''.format(prefix, user_agent.hex(), str(user_agent, encoding='utf-8')))
    print('{}{:32} start height {}'.format(prefix, start_height.hex(), unmarshal_uint(start_height)))
    print('{}{:32} relay {}'.format(prefix, relay.hex(), bytes(relay) != b'\0'))
    if len(extra) > 0:
        print('{}{:32} EXTRA!!'.format(prefix, extra.hex()))

def print_header(header, expected_cksum=None):
    """
    Report the contents of the given bitcoin message header
    :param header: bitcoin message header (bytes or bytearray)
    :param expected_cksum: the expected checksum for this version message, if known
    :return: message type
    """
    magic, command_hex, payload_size, cksum = header[:4], header[4:16], header[16:20], header[20:]
    command = str(bytearray([b for b in command_hex if b != 0]), encoding='utf-8')
    psz = unmarshal_uint(payload_size)
    if expected_cksum is None:
        verified = ''
    elif expected_cksum == cksum:
        verified = '(verified)'
    else:
        verified = '(WRONG!! ' + expected_cksum.hex() + ')'
    prefix = '  '
    print(prefix + 'HEADER')
    print(prefix + '-' * 56)
    prefix *= 2
    print('{}{:32} magic'.format(prefix, magic.hex()))
    print('{}{:32} command: {}'.format(prefix, command_hex.hex(), command))
    print('{}{:32} payload size: {}'.format(prefix, payload_size.hex(), psz))
    print('{}{:32} checksum {}'.format(prefix, cksum.hex(), verified))
    return command

def checksum(payload):
    """Get the checksum from the payload.

    Args:
        payload (bytes): The payload data

    Returns:
        bytes: the checksum
    """
    return hashlib.sha256(hashlib.sha256(payload).digest()).digest()[:4]

def create_message(command, payload=b""):
    """Create a bitcoin message

    Args:
        command (str): The command
        payload (bytes, optional): _description_. Defaults to b"".

    Returns:
        bytes: the final bitcoin message to send
    """
    command_bytes = command.encode('utf-8').ljust(12, b'\x00')  # Ensure 12 bytes, append 0 if needed on the right
    payload_length = len(payload)
    ret_checksum = checksum(payload)
    return MAGIC_BYTES + command_bytes + int32_t(payload_length) + ret_checksum + payload
 
def version_message():
    """Build a version payload

    Returns:
        bytes: the built version payload
    """
    version = uint32_t(VERSION)
    services = uint64_t(0)
    timestamp = uint64_t(int(time.time()))
    addr_recv_services = uint64_t(1)
    addr_recv_ip = ipv6_from_ipv4(BHOST)
    addr_recv_port = uint16_t(BPORT)
    addr_trans_services = uint64_t(1)
    cur_ip = socket.gethostbyname(socket.gethostname()) #relay IP address
    addr_trans_ip = ipv6_from_ipv4(cur_ip)
    addr_trans_port = uint16_t(PORT)
    nonce = uint64_t(0)
    user_agent = uint8_t(0) #empty user agent
    start_height = uint32_t(0)
    relay = uint8_t(0)  #disable transaction relay

    payload = (
        version +
        services +
        timestamp +
        addr_recv_services + addr_recv_ip + addr_recv_port +
        addr_trans_services + addr_trans_ip + addr_trans_port +
        nonce +
        user_agent +
        start_height +
        relay
    )
    return payload

def connect_to_node(ip, port):
    """initialize a connection to a bitcoin node

    Args:
        ip (str): the IP address of the node
        port (int): the port of the target node

    Returns:
        socket: the setup socket object
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((ip, port))
    print(f"Connected to node {ip}:{port}")
    return sock

def recv_all(sock, size):
    """get the data from the socket

    Args:
        sock (socket): the socket object
        size (int): the expected size of the data to receive

    Raises:
        ConnectionError: if the connection is broken

    Returns:
        bytes: the received data
    """
    data = b""
    while len(data) < size:
        part = sock.recv(min(4096, size - len(data))) #read up to 4096 bytes
        if not part:
            raise ConnectionError("Socket connection broken")
        data += part
    return data

def get_getblocks_message(starting_hash, stop_hash=bytearray(32)):
    """build the getblocks bitcoin message

    Args:
        starting_hash (bytes): the hash of the block to request from
        stop_hash (bytes, optional): the hash of the final block in case to request more blocks. Defaults to bytearray(32).
    Returns:
        bytes: the built getblocks message
    """
    version = uint32_t(VERSION)  #protocol version
    hash_count = compactsize_t(1)  #amount of hashes
    return version + hash_count + starting_hash + stop_hash

def parse_inv_message(payload):
    """parse the inventory message
    Args:
        payload (bytes): the payload data

    Returns:
        list: the list of inventory items
    """
    offset = 0
    count_bytes, count = unmarshal_compactsize(payload)
    offset += len(count_bytes)

    print(f"Inventory count: {count}")

    inventory = []
    for _ in range(count): #parse each inventory item
        type_id = unmarshal_uint(payload[offset:offset + 4]) #get invetory type
        hash_value = payload[offset + 4:offset + 36]
        inventory.append((type_id, hash_value.hex())) #
        offset += 36 #update count to the next 36 bit inventory item in the payload
    return inventory

def create_getdata_message(block_hash):
    """build the getdata message

    Args:
        block_hash (bytes): the hash of the block to request its data/transactions from

    Returns:
        bytes: the built getdata message
    """
    count = compactsize_t(1)  #how many hashes
    type_id = uint32_t(2)  #blocks type
    return count + type_id + block_hash

def find_target_block(sock):
    """find the target block from the P2P bitcoin network

    Args:
        sock (socket): the socket object

    Returns:
        list: the list of blocks that will contain the target block
    """
    last_hash = bytearray(32)  #Obtain the last hash from the Bitcoin network which is all 0s
    block_inventory = []
    found = False
    print(f'Requesting more blocks from starting block hash of 32 0\'s...')
    while not found:
            
            getblocks_payload = get_getblocks_message(last_hash)  # Request blocks starting from last_hash
            getblocks_packet = create_message("getblocks", getblocks_payload)
            sock.sendall(getblocks_packet)
            print_message(getblocks_packet, "sending")

            # Step 6: Receive inv response
            response = recv_all(sock, HDR_SZ)  # Receive header first
            payload_size = unmarshal_uint(response[16:20])
            response += recv_all(sock, payload_size)  # Receive the rest of the payload
            print_message(response, "received")

            # Parse the inv message
            inventory = parse_inv_message(response[HDR_SZ:])
            block_inventory.extend(inventory)  # Append new inventory to our list
            print(f"Received {len(inventory)} inventory items, checking for block {TARGET_BLOCK}")

            # Check if the target block is in the current inventory

            if len(block_inventory) >= TARGET_BLOCK:
                target_block = block_inventory[TARGET_BLOCK - 1]  # Adjust for zero-based index
                print(f"Block {TARGET_BLOCK} found: Type {target_block[0]}")
                found = True
                break
            else:
                last_hash = bytearray.fromhex(inventory[-1][1])  # Get the last hash from the inventory
                print(f'Not found yet, current inventory size: {len(block_inventory)}')
                
                #undo little endian
                temp_hash = inventory[-1][1]
                #flip every 2 characters
                littleendian = convert_endian(temp_hash)
                print(f"Getting more blocks from hash (converted to big-endian format): {littleendian}")
    
    return block_inventory

def handle_incoming_messages(sock):
    """Handle incoming messages from the bitcoin node after the version and verack messages

    Args:
        sock (socket): the socket object
    """
    while True:
        try:
            #process header to derive incoming payload size
            response = recv_all(sock, HDR_SZ) 
            payload_size = unmarshal_uint(response[16:20]) 
            response += recv_all(sock, payload_size) 
            command = print_message(response, "received") 
            
            #message handler
            if command == "ping":
                #sending back pong message to keep the P2P connection alive
                nonce = response[HDR_SZ:HDR_SZ + 8]  
                pong_message = create_message("pong", nonce) 
                sock.sendall(pong_message)
                print_message(pong_message, "sending")
            elif command == "addr":
                print("Received peer addresses")
            elif command == "feefilter":
                print("Received feefilter message")
                break  #Can stop dealing with incoming messages after this
            else:
                print(f"Got unknown command: {command}")

        except socket.timeout:
            print("Timeout Exceeded")
            break
        except socket.error as e:
            print(f"Socket error: {e}")
            break

def parse_block_message(payload):
    """Parse the block message

    Args:
        payload (bytes): the payload data

    Returns:
        dict: the parsed block message
    """
    #separate the block header and its payload   
    block_header = payload[:80]
    #get the block header version
    version = unmarshal_uint(block_header[:4])
    #get the previous block hash
    prev_block_hash = block_header[4:36][::-1].hex()  # Reverse for little-endian
    #get the Merkle root
    merkle_root = block_header[36:68][::-1].hex()  # Reverse for little-endian
    #get the timestamp
    timestamp = unmarshal_uint(block_header[68:72])
    #get nBits
    difficulty_target = block_header[72:76]
    #get the nonce
    nonce = unmarshal_uint(block_header[76:80])
    print(f"Block Header: \nVersion: {version}\nPrevious Block Hash: {prev_block_hash}\nMerkle Root: {merkle_root}\nTimestamp: {timestamp}\nDifficulty Target: {difficulty_target.hex()}\nNonce: {nonce}")
    payload = payload[80:]
    
    trans_count_bytes, trans_count = unmarshal_compactsize(payload) 
    payload = payload[len(trans_count_bytes):] #remove the transaction count from the payload
    
    # Extract the transactions
    transactions = []
    for i in range(trans_count):
        trans_bytes, transaction_details = parse_transaction(payload)
        transactions.append(transaction_details)
        payload = payload[len(trans_bytes):]

        # Print each transaction
        print(f"\nTransaction #{i + 1}:")
        print(f"TXID: {transaction_details['txid']}")
        print(f"Version: {transaction_details['version']}")
        print(f"Number of Inputs: {len(transaction_details['inputs'])}")
        for j, tx_input in enumerate(transaction_details['inputs']):
            print(f"  Input #{j + 1}: Previous TXID {tx_input['prev_txid']}\n\t\tNSEQUENCE: {hex(tx_input['sequence'])}")
        print(f"Number of Outputs: {len(transaction_details['outputs'])}")
        for k, tx_output in enumerate(transaction_details['outputs']):
            print(f"  Output #{k + 1}: Value {tx_output['value']} satoshis ({tx_output['value']/100000000} BTC)\n\t\tSCRIPTPUBKEY (HEX): {tx_output['script']}")
        print(f"Locktime: {transaction_details['locktime']}")

    return {
        "header": block_header,
        "count": trans_count,
        "transactions": transactions,
    }

def parse_transaction(payload):
    """Parse the transaction message

    Args:
        payload (bytes): the payload data
        
    Returns:
        tuple: the raw transaction data and the parsed transaction
    """
    
    offset = 0

    #get the transaction version
    version = unmarshal_uint(payload[offset:offset + 4])
    offset += 4

    #get the input count and extract the input transactions
    input_count_bytes, input_count = unmarshal_compactsize(payload[offset:])
    offset += len(input_count_bytes)

    #iterate and parse each input transaction to store in a dict
    inputs = []
    for _ in range(input_count):
        prev_txid = payload[offset:offset + 32][::-1].hex()  #convert to big-endian to match the website output
        offset += 32
        index = unmarshal_uint(payload[offset:offset + 4])
        offset += 4

        #extract script length and script
        script_len_bytes, script_len = unmarshal_compactsize(payload[offset:])
        offset += len(script_len_bytes)

        script = payload[offset:offset + script_len].hex()
        offset += script_len

        #extract sequence
        sequence = unmarshal_uint(payload[offset:offset + 4])
        offset += 4

        inputs.append({
            "prev_txid": prev_txid,
            "index": index,
            "script": script,
            "sequence": sequence
        })

    #now extract the output count
    output_count_bytes, output_count = unmarshal_compactsize(payload[offset:])
    offset += len(output_count_bytes)

    #get the output transactions
    outputs = []
    for _ in range(output_count):
        #extract value and script
        value = unmarshal_uint(payload[offset:offset + 8])
        offset += 8

        script_len_bytes, script_len = unmarshal_compactsize(payload[offset:])
        offset += len(script_len_bytes)

        script = payload[offset:offset + script_len].hex()
        offset += script_len

        outputs.append({
            "value": value,
            "script": script
        })

    #extract locktime
    locktime = unmarshal_uint(payload[offset:offset + 4])
    offset += 4

    #store the raw transaction data for later extra credit use
    raw_transaction = payload[:offset]

    # Compute transaction hash (TXID)
    txid = hashlib.sha256(hashlib.sha256(raw_transaction).digest()).digest()[::-1].hex() #convert to big-endian to match the website output

    return raw_transaction, {
        "txid": txid,
        "version": version,
        "inputs": inputs,
        "outputs": outputs,
        "locktime": locktime,
        "raw": raw_transaction.hex()
    }

def modify_transaction(transaction):
    """modify the transaction by adding the first byte by 1

    Args:
        transaction (bytes): the transaction data

    Returns:
        bytes: the modified transaction data
    """
    #Change the first byte of the transaction
    old_transaction = transaction
    modified_transactions = bytearray(transaction) #convert to bytearray to modify
    modified_transactions[0] = (modified_transactions[0] + 1) % 256 #do % 256 to keep it in the range of 0-255
    print(f"\n\nFlipping First Transaction's First Bit\nOld Transaction: {old_transaction.hex()}\nModified Transaction: {modified_transactions.hex()}")
    return modified_transactions

def compute_merkle_root(transactions):
    """compute the Merkle root from the input transactions

    Args:
        transactions (list): the list of transactions

    Returns:
        bytes: the computed merkle root
    """
    hashes = [hashlib.sha256(transaction).digest() for transaction in transactions] #convert each transaction into its SHA256 hash
    while len(hashes) > 1: #until we have the root
        if len(hashes) % 2 != 0: #if the number of hashes is odd, duplicate the last one
            hashes.append(hashes[-1]) #append the last hash to the list
        
        hashes = [hashlib.sha256(hashes[i] + hashes[i + 1]).digest() for i in range(0, len(hashes), 2)] #combine the hashes in pairs and hash them
    return hashes[0] #return the root

def update_block_header(block_header, new_merkle_root):
    """update the block header with the new input merkle root

    Args:
        block_header (_type_): _description_
        new_merkle_root (_type_): _description_

    Returns:
        _type_: _description_
    """
    updated_header = block_header[:36] + new_merkle_root + block_header[68:] #replace the Merkle root in the block header
    return updated_header

def simulate_rejection(block_header, original_merkle_root, new_merkle_root, difficulty_target):
    """simulate the rejection of a modified block from the bitcoin P2P network

    Args:
        block_header (bytes): the block header
        original_merkle_root (bytes): the original merkle root
        new_merkle_root (bytes): the new merkle root
        difficulty_target (bytes): the difficulty target
    """
    block_hash = hashlib.sha256(hashlib.sha256(block_header).digest()).digest()[::-1]
    print(f"New Block Hash: {block_hash[::-1].hex()}") #convert to big-endian to match the website output
    
    #Case 1: Check if the Merkle root is still the same
    if original_merkle_root != new_merkle_root:
        print("Work Rejected: Invalid Merkle root, it should be matching the block header.")
    
    #Case 2: Check if the block hash still meets the difficulty target
    target_value = int.from_bytes(difficulty_target, byteorder='big')
    block_hash_value = int.from_bytes(block_hash, byteorder='big')
    
    if block_hash_value > target_value:
        print("Work Rejected: Proof-of-work invalid. The block hash does not meet the difficulty target.")
    else:
        print("Work is accepted and is valid.")

def convert_endian(hex_string):
    
    if len(hex_string) % 2 != 0:
        raise ValueError("Hex string must have even len")

    #flip endian
    reversed_bytes = ''.join(reversed([hex_string[i:i+2] for i in range(0, len(hex_string), 2)]))
    return reversed_bytes

def main():
    """Main function to connect to the bitoin node in a P2P network and simulate the rejection of a modified block"""
    try:
        #connect to the Bitcoin node
        sock = connect_to_node(BHOST, BPORT)
        sock.settimeout(10)

        #Step 1: send the version message
        v_message = version_message()
        v_packet = create_message("version", v_message)
        sock.sendall(v_packet)
        print_message(v_packet, "sending")

        #Step 2: receive and handle the version response
        response = recv_all(sock, HDR_SZ)  #Get the header first
        payload_size = unmarshal_uint(response[16:20])
        response += recv_all(sock, payload_size) 
        print_message(response, "received")
        
        #Step 3: send the verack message
        verack_packet = create_message("verack")
        sock.sendall(verack_packet)
        print_message(verack_packet, "sending")

        # Step 4: receive and handle the verack response
        response = recv_all(sock, HDR_SZ)  # Verack has no payload
        print_message(response, "received")
        
        # Step 5: Handle additional messages that would be sent after (e.g., ping, sendheaders, sendcmpct)
        handle_incoming_messages(sock)
            
        # Step 6: Send getblocks message
        block_inventory = find_target_block(sock)
        
        #print out target block from the inventory
        print(f'Inventory: {len(block_inventory)}')
        print(f"Target block\'s ({TARGET_BLOCK}) hash converted to big endian for readability: {convert_endian(block_inventory[TARGET_BLOCK - 1][1])}")

        # Step 7: Request the full block with getdata message
        block_hash = bytearray.fromhex(block_inventory[TARGET_BLOCK - 1][1])
        getdata_message = create_getdata_message(block_hash) #Create getdata message
        getdata_packet = create_message("getdata", getdata_message)
        sock.sendall(getdata_packet)
        print_message(getdata_packet, "sending")
        
        # Step 8: Receive block response
        response = recv_all(sock, HDR_SZ)  # Receive header first
        payload_size = unmarshal_uint(response[16:20])
        response += recv_all(sock, payload_size)  # Receive the rest of the payload
        
        print_message(response, "received")
        
        # Step 9: Parse the block transaction message and print the transactions
        print("\nTarget block...")
        parsed_block = parse_block_message(response[HDR_SZ:])

        # Step 10: Modify the first transaction by incrementing the first hex byte by 1
        transactions = [bytearray.fromhex(tx["raw"]) for tx in parsed_block["transactions"]]
        modified_tx = modify_transaction(transactions[0])  # Modify the first transaction
        transactions[0] = modified_tx

        # Step 11: Update/Recompute the Merkle root
        print(f"\n\nComputing new Merkle root for the modified block...")
        new_merkle_root = compute_merkle_root(transactions)
        print(f"\nOld Merkle Root: {parsed_block['header'][36:68][::-1].hex()}\nNew Merkle Root: {new_merkle_root[::-1].hex()} ")  # Reverse for little-endian to match website output

        # Step 12: Update the block header with the new Merkle root to simulate a modified block
        updated_header = update_block_header(parsed_block["header"], new_merkle_root)

        # Step 13: Simulate how the Bitcoin P2P network would reject the modified block
        print("\n\nSimulating block rejection...")
        old_merkle_root = parsed_block["header"][36:68]
        old_difficulty_target = parsed_block["header"][72:76]
        
        simulate_rejection(updated_header, old_merkle_root, new_merkle_root, old_difficulty_target)

        # Close the connection
        sock.close()
        print("Connection successfully closed")
        
    except (socket.error, socket.timeout) as e:
        print(f"Failed to connect or exchange messages: {e}")



if __name__ == "__main__":
    main()