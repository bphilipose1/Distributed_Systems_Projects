"""
Multi-threaded Bully Algorithm Program

Description:
This program will create 3 nodes, and each will start up and connect to a GCD, send "BEGIN" and retrieve a list of members/targets and the port to contact them on.
From there on it will follow the bully algorithm and ensure a leader is elected when one goes down. The messages sent and recieved will be printed to the console.



NOTE: 
EXTRA CREDIT PROBING - Probing is done for each node on a async thread if they are a follower, and is done for the specified random time intervals of .5 to 3 seconds. Each probe waits for an OK
from the LEADER currently defined. If no leader is found, it will contact GCD and then start an election.

EXTRA CREDIT FEIGNING FAILURE - This feature is implemented. The nodes have a function that signal the handler thread to freeze, and drop requests. The main function initiates a killed leader by taking
the leader node and toggling on the 'play_dead_script' function. Then the main function waits random intervals between (1 to 4 seconds) before toggling 'play_dead_script' to be off. This enabling and disabling of the leader
is repeated indefinetly, with 0 to 10 second breaks in between. Also since feining is set to 0-4 seconds long, the nodes dont have enough time for election. But i tested and they do work as planned if i 
increase feining time of leader to be long enough for the other nodes to elect a new leader.

CMD use:
    Starting GCD...
    $ python3 gcd2.py [port_number]
    
    Starting Lab2.py
    
    $ python3 lab2.py [host] [start_port_number]
    
    - host -> The domain adress for the Nodes to run on. (for simplicity, all nodes in main function use same host since it is all on the same server.)
    - start_port_number -> The port number to create a node on and around (ie start_port_number + or - 1 etc.)
    
:Authors: Benjamin Philipose
:Date: 2024-10-14
"""

import socket
import threading
import pickle
import time
import random
import sys
import socketserver
from queue import Queue
import datetime
  

#request handler for Node
class NodeRequestHandler(socketserver.BaseRequestHandler):
    """A request handler class for processing incoming messages to a node."""
    def handle(self):
        try:
            # Read and process the message
            data = self.request.recv(1024)  
            message = pickle.loads(data) 
            
            cur_thread = threading.current_thread()
            #Queue up the message request for handler
            self.server.recv_queue.put(message) 

        except Exception as e:
            print(f"Error handling request: {e}")


# Create the Node class
class Node:
    """
        Represents a node in a distributed system that utilizes the Bully Algorithm for electing a new leader node
        
        Each node has a unique identity and if it starts up, notices leader is down by probing, or is sent an election message, the node participates in elections to find out who the new leader is.
        TCP is the primary communication protocal. 
        
        NOTE: PROFESSOR LUNDEEN DID PERMIT THIS, AND WANTED ME TO MENTION FOR THE TA
        THE LISTENER IS BINDED TO THE NODES HOST NAME AND PORT
        THE SENDER IS DYNAMICALLY BINDED. SO TO KNOW WHERE THE MESSAGES ARE SENT FROM, THE SENDERS IDENTITY IS ADDED TO THE DATA SECTION OF THE MESSAGE. 
        
        DESIGN: Each node has a listener, handler, sender, and probing threads. All of them are Async. I utilized the producer and consumer design for each nodes requests.
        listeners -> [recv_queue] -> handler -> [sender_queue] -> sender
        
        Attributes:
            IDENTITY (tuple): A tuple containing the days until the user's mother's next birthday and the SU ID.
            host (str): The host IP address of the node.
            port (int): The port number on which the node listens for connections.
            GCD_HOST (str): The host IP address of the GCD.
            GCD_PORT (int): The port number of the GCD.
            
            leader_ID (tuple): holds the IDENTITY tuple of the new elected leader.
            node_state (string): holds the state that the node object is currently representing. STARTUP, CANDIDATE, LEADER, TRASH_CANDIDATE, FOLLOWER.
            members (dict): Holds the members list GCD gave, and updates for messages it recieves from current and new members it.
            
            play_dead (bool): Indicates whether the node is currently in a failure state.
            ok_recieved (bool): Indicates whether the ndoe got an OK response.
            
            recv_queue (queue.Queue): The thread safe datastructure (queue) that holds incoming messages for processing.
            sender_queue (queue.Queue): The thread safe datastructure (queue) that holds  messages ready to be sent out.
    """
    def __init__(self, input_host, input_port,input_days = None, input_SU_ID = None, input_gcd_host='cs2.seattleu.edu', input_gcd_port='50040'):
        """
            Initializes a new node in the distributed system using the Bully Algorithm for leader election.

            The node is initialized with its identity (days to mom's birthday and SU ID), host, and port information. 
            Additionally, various state variables, such as leader ID, node state, and membership list, are initialized. 
            A message queue for receiving and sending messages is also set up, along with threading locks and thread safe flags 
            for synchronization between concurrent threaded operations.

            Args:
                input_host (str): The ip/domain where this node will listen for connections.
                input_port (int): The port number where this node will listen for connections.
                
                input_days (int, optional): Days until the user's mother's next birthday. Defaults to a random value between 1 and 365 if not provided.
                input_SU_ID (int, optional): The SU ID of the user. Defaults to a random 7-digit number if inputted number is invalid or not provided.
                
                input_gcd_host (str, optional): The ip address of the GCD. Defaults to 'cs2.seattleu.edu'.
                input_gcd_port (int, optional): The port number of the GCD. Defaults to '50040'.

            Attributes:
                host (str): The ip/domain of the node.
                port (int): The port number for the node.
                
                GCD_HOST (str): The IP address of the GCD.
                GCD_PORT (int): The port number of the GCD.
                
                IDENTITY (tuple): A tuple representing the node's identity (days to mom's birthday, SU ID).
                
                leader_ID (tuple): The ID of the elected leader.
                leader_ID_lock (threading.Lock): A lock for thread-safe access and update to the leader ID.
                
                node_state (str): The current state of the node (Ex: 'STARTUP', 'LEADER', etc.)
                node_state_lock (threading.Lock): A lock to protect access and update to the node's state.
                
                valid_states (set of strings): A set of valid states (stings) the node can assume.
                
                members (dict): A dictionary of known group members, (ID):(host, port).
                member_lock (threading.Lock): A lock for thread-safe access to the members list.
                
                play_dead_event (threading.Event): An thread safe event flag for whether the node should play dead.
                recv_queue (Queue): A queue to store received requests.
                sender_queue (Queue): A queue to store send jobs.
                
                ok_received (threading.Event): An thread safe event to signal an Ok was given back.
                
                OK_TIMEOUT (int): Timeout duration for receiving an 'OK' response after sending a message prior.

            Returns:
                None
        """
        self.host = input_host
        self.port = input_port
        self.GCD_HOST = input_gcd_host
        self.GCD_PORT = int(input_gcd_port)
        
        #create identity (days to mom's birthday, SU ID)
        if input_days == None:
            DAYS_TO_MOMS_BIRTHDAY = random.randint(1, 365)
        else:
            DAYS_TO_MOMS_BIRTHDAY = input_days % 365
        if input_SU_ID == None or 1000000 > input_SU_ID or 9999999 < input_SU_ID:
            SU_ID = random.randint(1000000, 9999999)
        else:
            SU_ID = input_SU_ID
            
        self.IDENTITY = (DAYS_TO_MOMS_BIRTHDAY, SU_ID)

        #Election state variables
        self.leader_ID = None  #ID of the current supposed leader
        self.leader_ID_lock = threading.Lock()  # Lock for thread-safe access to leader_ID
        
        self.node_state = 'STARTUP'
        self.node_state_lock = threading.Lock()  #Lock to protect state
        self.valid_states = {'CANDIDATE', 'LEADER', 'TRASH_CANDIDATE', 'FOLLOWER'}
        
        self.members = {}  #store all known members of the group's domain and port
        self.member_lock = threading.Lock()
        
        self.play_dead_event = threading.Event()
        self.play_dead_event.set()
        
        #Queue to store recieved requests
        self.recv_queue = Queue()
        
        #Queue to store messages needed to be sent
        self.sender_queue = Queue()

        #Threaded..
        self.ok_received = threading.Event()

        self.OK_TIMEOUT = 2

        self.log(f'HELLO I AM {self.IDENTITY}')
        self.start_up()

    def start_up(self):
        """
        Initializes the nodes concurrent services by starting the threads.
        Sends a 'BEGIN' message to join the GCD group.
        """
        #start the listener thread for listening for incoming messages and put in sender_queue
        self.start_listener()

        #start the handler thread for handling incoming messages form recv_queue
        threading.Thread(target=self._process_messages, daemon=True).start()
        
        #start the sender thread for sending messages from sender_queue
        threading.Thread(target=self._process_send_queue, daemon=True).start()
        
        #INITIAL NON SEQUENTIAL send message to GCD to join the group on MAIN THREAD
        self.send_message(None, self.GCD_HOST, self.GCD_PORT, ('BEGIN', (self.IDENTITY, (self.host, self.port))))  
        
        # Create a thread that randomly sends a PROBE message to the leader whenever the node is in FOLLOWER state
        threading.Thread(target=self._send_probe_periodically, daemon=True).start()

    def play_dead_script(self):
        """
        Toggle between 'alive' and 'dead' states for the node.
        In dead state the nodes handler drops requests. In alive state node reboots and re-registers.
        """
        if self.play_dead_event.is_set():  #node is alive, pretent to play dead
            self.log(f'{self.IDENTITY}: Playing dead now. Dropping requests.')
            self.play_dead_event.clear()
        else:  #node is currently playing dead, bring it back to life
            self.log(f'{self.IDENTITY}: Coming back alive now.')
            self.play_dead_event.set() 
            
            #restart and re-register with GCD, and potentially start an election
            self.send_message(None, self.GCD_HOST, self.GCD_PORT, ('BEGIN', (self.IDENTITY, (self.host, self.port))))
   
    def start_listener(self):
        """
        sets up and starts the ThreadingTCPServer to listen for incoming messages.
        Runs the listener in a new thread and attaches the recv_queue to queue up messages for handling.
        """
        #create and start the ThreadingTCPServer
        server = socketserver.ThreadingTCPServer((self.host, self.port), NodeRequestHandler)
        server.node = self  
        server.recv_queue = self.recv_queue  #give the recv_queue access to queue for the handler

        #start the listener section in a new thread
        self.server_thread = threading.Thread(target=server.serve_forever, daemon=True)
        self.server_thread.start()
   
    def _send_probe_periodically(self):
        """
        Periodically (randomly between .5 and 3 seconds) sends a probe message to the current leader if the node is currently in follower state.
        """
        while True:
            #only send PROBE if the node is in FOLLOWER state
            if self.get_state() == 'FOLLOWER':
                #get the leader_ID and send a PROBE
                leader = self.get_leader_ID()
                if leader is not None:
                    self.log(f"{self.IDENTITY}: Sending PROBE to leader {leader}")
                    
                    with self.member_lock:
                        leader_host, leader_port = self.members.get((leader[0], leader[1]), (None, None))
                    
                    if leader_host and leader_port:
                        self.send_message(leader, leader_host, leader_port, ('PROBE', (self.IDENTITY, (self.host, self.port))))
                        self.wait_for_ok_from_probe(leader_host, leader_port)
                    else:
                        self.log(f"{self.IDENTITY}: Cannot find leader address to send PROBE.")

                #wait random time between .5 and 3 seconds before the next probe
                sleep_time = random.uniform(0.5, 3.0)
                time.sleep(sleep_time)
            else:
                #If not a FOLLOWER, sleep then check again
                time.sleep(5)

    def wait_for_ok_from_probe(self, leader_host, leader_port):
        """
        Waits for an OK response from the leader after sending a PROBE. 
        Contact GCD if no response is received within the timeout.
        """
        self.log(f"{self.IDENTITY}: Waiting for OK response from {leader_host}:{leader_port} for the PROBE...")

        try:
            if self.ok_received.wait(timeout=self.OK_TIMEOUT):
                self.ok_received.clear()
                #received ok, leader is alive
                self.log(f"{self.IDENTITY}: Received OK from {leader_host}:{leader_port}, leader is alive.")
            else:
                #no ok received within the timeout, leader is assumed dead
                self.log(f"{self.IDENTITY}: No OK response, leader is assumed dead. Contacting GCD.")
                # Re-register with GCD
                self.send_message(None, self.GCD_HOST, self.GCD_PORT, ('BEGIN', (self.IDENTITY, (self.host, self.port))))
        except Exception as e:
            self.log(f"Error while waiting for 'OK' response: {e}")

    def _process_messages(self):
        """
        Processes messages from the recv_queue sequentially. Ignores messages if the node is playing dead.
        """
        while True:
            #this call will block the thread until a new message is put in the queue
            message = self.recv_queue.get()

            if self.play_dead_event.is_set():  #ff the node is alive, process the message
                self.log(f"{self.IDENTITY} Processing message: {message}")
                self._handle_message(message)
            else:  #if the node is playing dead, ignore the message
                self.log(f"{self.IDENTITY} Ignoring message while playing dead: {message}")

            # Mark the task as done, whether processed or ignored
            self.recv_queue.task_done()
                
    def _handle_message(self, message):
        """
        Handles incoming messages and responds based on message type (ELECTION, PROBE, COORD, OK).
        """
        if isinstance(message, tuple):
            message_type, data = message
        elif isinstance(message, dict):
            #Message is from GCD containing members list, update current members then
            with self.member_lock:
                self.members.update(members)
        else:
            self.log(f"MESSAGE CONTAINS INCORRECT FORMAT: {message}")

            return
        
        if message_type == 'ELECTION':
            sender_identity = data[0]  #the senders identity (days_to_moms_birthday, SU_ID)
            sender_host = data[1][0]   #the senders host
            sender_port = data[1][1]   #the senders port
            received_members = data[2] #received member dictionary

            #send OK response back to the sender
            self.send_message(sender_identity, sender_host, sender_port, ('OK', (self.IDENTITY, (self.host, self.port))))
            
            #update with the recieved member dictionary
            with self.member_lock:
                self.members.update(received_members)
    
            #start an election if the node isn't already in an election state
            if self.get_state() not in ['CANDIDATE', 'TRASH_CANDIDATE']:
                self.start_election()
                
        elif message_type == 'PROBE':
            #send OK back to the sender
            sender_host = data[1][0]
            sender_port = data[1][1]
            sender_identity = data[0]
            self.send_message(sender_identity, sender_host, sender_port, ('OK', (self.IDENTITY, (self.host, self.port))))
        
        elif message_type == 'COORD':
            #set state to FOLLOWER as new leader has been found
            self.set_state('FOLLOWER')
            sender_identity = data[0]
            sender_host = data[1][0]
            sender_port = data[1][1]

            #Update the leader ID
            self.set_leader_ID(sender_identity)
            
            #Update Leaders member entry
            with self.member_lock:
                self.members[(sender_identity[0], sender_identity[1])] = (sender_host, sender_port)

            self.log(f"{self.IDENTITY}: COORD received from {sender_identity}")

        elif message_type == 'OK':
            sender_identity = data[0]
            temp_state = self.get_state()
            if temp_state == 'CANDIDATE':  #only care about OK if still in an election
                self.ok_received.set()
                self.set_state("TRASH_CANDIDATE")  
            elif temp_state == 'FOLLOWER' and sender_identity == self.get_leader_ID(): #check we are a follower and if ok is from the leader
                self.ok_received.set()
                self.log('LEADER IS ALIVE')
               
    def send_message(self, target_identity, target_host, target_port, message):
        """
        Sends a message to the target node or GCD. Deals with 'BEGIN' on main thread for GCD communication. Else it puts in a queue sending by sender thread.
        """
        if message[0] == 'BEGIN':  #Special case to talk to GCD
            with self.member_lock:
                self.members = self.join_gcd_group(target_host, target_port, message)
            self.log(f"Received: {self.members.items()}")

            self.start_election()
        else:
            #Put message details into the sender_queue
            self.sender_queue.put((target_host, target_port, message))

    def _process_send_queue(self):
        """
        Processes and sends messages from the sender_queue using a new socket for each outgoing message.
        """
        while True:
            try:
                #Get the next message from the queue (blocking thread call)
                target_host, target_port, message = self.sender_queue.get()
                
                self.log(f"{self.IDENTITY} prepping to send message to: {target_host}:{target_port} -> {message}")


                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.settimeout(5)  #timeout for the socket connection
                    try:
                        s.connect((target_host, target_port))
                        self._send_message(s, message)  # Pass the socket to the message sending helper function
                    except socket.error as e:
                        self.log(f"Socket error: {e}")
                        continue  #skip to the next message if connection fails
            except Exception as e:
                self.log(f"Error in sending thread: {e}")

            self.sender_queue.task_done()

    def _send_message(self, s, message):
        """Send the actual message using the provided socket."""
        try:
            #serialize and send the message
            temp_msg = pickle.dumps(message)
            try:
                s.sendall(temp_msg)
            except socket.error as e:
                self.log(f"Error sending message: {e}")
                return

            #handling election responses if it occurs
            if message[0] == 'ELECTION':
                try:
                    response = s.recv(1024)
                    if not response:
                        return
                    response_message = pickle.loads(response)
                    if response_message[0] == 'OK':
                        self.recv_queue.put(('OK', message))
                except socket.timeout:
                    self.log(f"socket timed out waiting for OK")
                except EOFError:
                    self.log(f"partial response")
                except socket.error as e:
                    self.log(f"Socket error: {e}")
        except socket.error as e:
            self.log(f"Socket error: {e}")
    
    def join_gcd_group(self, target_host, target_port, message):
        """Sends message to GCD and gets member list in return"""
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                #connect to GCD
                s.connect((target_host, target_port))
                
                #send BEGIN to GCD
                temp_msg = pickle.dumps(message)
                s.sendall(temp_msg)
                
                #get back response
                rec_data = s.recv(1024)
                
                #convert from binary to readable format
                member_list = pickle.loads(rec_data)
                return member_list
        except socket.error as e:
            self.log(f"Socket error: {e}")
            return  
    
    def start_election(self):
        """
        Initiates an election.
        """
        self.log(f'{self.IDENTITY}: Starting Election...')
        self.set_state('CANDIDATE')
        self.ok_received.clear()
        self.send_election_messages()
        threading.Thread(target=self.wait_for_ok_response, daemon=True).start()  #spin up a thread to react to if given or not given an ok.

    def send_election_messages(self):
        """Send election messages to nodes with higher identity value than itself."""
        with self.member_lock:
            temp_members = self.members
        for identity, target in temp_members.items():
            if isinstance(identity[0], int) and isinstance(identity[1], int):
                if identity[0] > self.IDENTITY[0] or (identity[0] == self.IDENTITY[0] and identity[1] > self.IDENTITY[1]):
                    self.send_message(identity, target[0], target[1], ('ELECTION', (self.IDENTITY, (self.host, self.port), temp_members)))
            else:
                self.log(f"Invalid identity found for {identity}: {target}")

    def wait_for_ok_response(self):
        """Function waits for OK asynchronously and responds to if an OK is given or not."""   
        if self.ok_received.wait(timeout=self.OK_TIMEOUT):
            self.ok_received.clear()
            #If ok recieved, set state to TRASH_CANDIDATE
            if self.get_state() == 'CANDIDATE':  #If still candidate then proceed
                self.set_state('TRASH_CANDIDATE')
        else:
            #No OK response before timeout, declare yourself as LEADER if still a candidate
            if self.get_state() == 'CANDIDATE':  #If still candidate then proceed
                self.set_state('LEADER')
    
    def bcast_coord(self):
        """Broadcast message that node is the leader, and queue messages in the sender_queue to be sent."""
        with self.member_lock:
            temp_members = self.members
        for identity, target in temp_members.items():
            #extra safety check just in case
            if isinstance(identity, tuple) and isinstance(identity[0], int) and isinstance(identity[1], int):
                if identity != self.IDENTITY:
                    self.send_message(identity, target[0], target[1], ('COORD', (self.IDENTITY, (self.host, self.port))))
            else:
                self.log(f"Invalid identity found for {target}: {identity}")

    def get_state(self):
        """Lock when reading state to avoid race conditions"""
        with self.node_state_lock:
            return self.node_state

    def set_state(self, state):
        """Lock when changing state to avoid race conditions"""
        if state in self.valid_states:
            with self.node_state_lock:  
                if self.node_state != state:
                    self.node_state = state
                    if self.node_state == 'CANDIDATE':
                        self.log(f'{self.IDENTITY}: I AM CANDIDATE')
                        
                    elif self.node_state == 'LEADER':
                        self.bcast_coord()
                        self.set_leader_ID(self.IDENTITY)
                        self.log(f'{self.IDENTITY}: I AM SUPREME LEADER')
                        
                    elif self.node_state == 'TRASH_CANDIDATE':#TEMPORARY STATE that will decay after 5s
                        self.log(f'{self.IDENTITY}: I AM TRASH CANDIDATE')
                        
                        #10 sec timer to revert back to CANDIDATE if no COORD is received
                        threading.Timer(10, self.check_if_still_trash_candidate).start()
                        
                    else:
                        self.log(f'{self.IDENTITY}: I AM A FOLLOWER')
        else:
            self.log(f"Invalid State: {state}")
    
    def check_if_still_trash_candidate(self):
        """If still in TRASH_CANDIDATE state, switch back to CANDIDATE and start a new election"""
        with self.node_state_lock:
            if self.node_state == 'TRASH_CANDIDATE':
                self.log(f"{self.IDENTITY}: Still TRASH_CANDIDATE after 10 seconds, re-initiating election.")
                self.start_election()
   
    def get_leader_ID(self):
        """Getter for leader_ID with thread safety"""
        with self.leader_ID_lock:
            return self.leader_ID

    def set_leader_ID(self, new_leader_ID):
        """Setter for leader_ID with thread safety"""
        with self.leader_ID_lock:
            self.leader_ID = new_leader_ID
            print(f'{self.IDENTITY}: I view {self.leader_ID} as LEADER!')

    def log(self, message):
        """Helper function to log messages with a timestamp."""
        timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        print(f"[{timestamp}] {message}")

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python client.py HOST PORT")
        exit(1)

    node_host = sys.argv[1] 
    node_port = int(sys.argv[2]) 

    #Test 1: start multiple nodes and verify the election process.
    print("Test 1: Multiple nodes joining the group, starting election.")
    node1 = Node(node_host, node_port, 61)    
    time.sleep(2)

    node2 = Node(node_host, node_port - 1, 154)  
    time.sleep(6)
    
    node3 = Node(node_host, node_port + 2, 295)
    time.sleep(10)
    
        
    #Verify election results after nodes have joined
    print("\n\nFinal Check of Node States after election")
    print(f"Node 1 ({node1.IDENTITY}) State: {node1.get_state()} Leader: {node1.leader_ID}")
    print(f"Node 2 ({node2.IDENTITY}) State: {node2.get_state()} Leader: {node2.leader_ID}")
    print(f"Node 3 ({node3.IDENTITY}) State: {node3.get_state()} Leader: {node3.leader_ID}")
    print("All nodes should agree on the leader after the election.")

    #limit randomness, for ease of observing behavior
    rand_time_intevral = random.randint(0, 10)
    rand_down_duration = random.randint(1, 4)


    while True:
        time.sleep(rand_time_intevral)
        
        print('LEADER IS HIT BY A STORM AND OFFLINE')
        node3.play_dead_script()
        
        time.sleep(rand_down_duration)
        
        # Verify the new election results
        print("\n\nFinal Check of Node States after Node 1 recovers")
        print(f"Node 1 ({node1.IDENTITY}) State: {node1.get_state()} Leader: {node1.leader_ID}")
        print(f"Node 2 ({node2.IDENTITY}) State: {node2.get_state()} Leader: {node2.leader_ID}")
        print("All nodes should have a consistent view of the new leader after recovery.")
        
        
        
        print('WHAT IS THIS THE OLD LEADER IS BACK!!!')
        node3.play_dead_script() # Start up third node again

        time.sleep(20)
        
        # Verify the new election results
        print("\n\nFinal Check of Node States after Node 1 recovers")
        print(f"Node 1 ({node1.IDENTITY}) State: {node1.get_state()} Leader: {node1.leader_ID}")
        print(f"Node 2 ({node2.IDENTITY}) State: {node2.get_state()} Leader: {node2.leader_ID}")
        print(f"Node 3 ({node3.IDENTITY}) State: {node3.get_state()} Leader: {node3.leader_ID}")
        print("All nodes should have a consistent view of the new leader after recovery.")


