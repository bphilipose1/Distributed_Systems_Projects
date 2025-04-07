"""
CPSC 5520, Seattle University
:Authors: Benjamin Philipose
:Version: f24-01
"""

import socket
import time
import math
from fxp_bytes_subscriber import deserialize_message, serialize_address
from bellman_ford import BellmanFord 
import fxp_bytes
from datetime import datetime, timedelta
import queue
import sys
import threading
class ArbitrageDetector:
    """
    Detects arbitrage opportunities in the forex market by subscribing to a forex provider, maintaining a graph of exchange rates and checking for negative cycles in the graph with Bellman-Ford algorithm.
    """
    def __init__ (self, address):
        """
        Initialize the ArbitrageDetector object with the forex provider address and the subscriber address.

        Args:
            address (_type_): A tuple containing the IP address and port of the forex provider.
        """
        self.VALIDITY_PERIOD = timedelta(seconds=1.5)
        
        #initialize UDP subscriber
        self.provider_address = address
        host_name = socket.gethostbyname(socket.gethostname())
        self.subscriber_address = (host_name, 50030)
        
        #initialize Bellman-Ford graph
        self.graph = BellmanFord()

        #track latest timestamps for each currency pair
        self.latest_timestamps = {}
        
        # Queue for incoming 
        self.message_queue = queue.Queue()
        

    def subscribe_to_forex_provider(self):
        """
        Send a subscription message to the forex provider to subscribe to the forex quotes.
        """
        #create the subscription message
        subscription_msg = serialize_address((self.subscriber_address[0], self.subscriber_address[1]))
        
        #send subscription message to forex provider
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.sendto(subscription_msg, (self.provider_address[0], self.provider_address[1]))
        print(f"Subscribed to Forex Provider at {self.provider_address[0]}:{self.provider_address[1]}")

    def listener_thread(self):
        """
        Listens on a UDP socket for incoming forex quotes from the forex provider. Pushes the quotes to the message queue after deserializing them.
        """
        #create a UDP socket
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.bind(self.subscriber_address)
        
        while True:
            data, _ = sock.recvfrom(4096)
            quotes = deserialize_message(data)
            self.message_queue.put(quotes)

    def check_arbitrage(self, tolerance = 1e-12, start_currency = 'USD'):
        """
        Run the Bellman-Ford algorithm to check for negative cycles in the graph. If a negative cycle is found, print the arbitrage steps and show the profit.

        Args:
            tolerance (_type_, optional): A small tolerance for detecting arbitrage oppertunities in floating point calculations that can sometimes have rounding error. Defaults to 1e-12.
            start_currency (str, optional): The Base currency to start the arbitrage detection cycle and start and end with the arbitrage. Defaults to 'USD'.
        """
        distances, predecessors, negative_cycle_edge = self.graph.shortest_paths(start_currency, tolerance)
        #check if there is a negative cycle
        if negative_cycle_edge:   
            #using predecessors, go from u to v, then run shortest_paths to find best path from v to u
            start_amount = 100
            u, v = negative_cycle_edge
            cycle = [v]  
            current = u #tracing should start at u
            max_iterations = len(self.graph.vertices) #safegaurd against infinite
            #trace back the cycle
            for _ in range(max_iterations):
                if current is None or current in cycle:
                    break  # End if tracing back hits a loop or a dead end
                cycle.append(current)
                current = predecessors.get(current)
            
            if current != v: #cannot loop back easily
                return    
            
            cycle.append(v)
            cycle.reverse()
        
            # Print the detailed arbitrage steps and calculate profit
            print("ARBITRAGE:")
            current_amount = start_amount
            print(f"\tstart with {start_currency} {start_amount}")

            for i in range(len(cycle) - 1):
                currency1 = cycle[i]
                currency2 = cycle[i + 1]
                rate = 10 ** (-self.graph.edges[currency1][currency2]) #undo log of rate
                next_amount = current_amount * rate
                print(f"\texchange {currency1} for {currency2} at {rate} --> {currency2} {next_amount}")
                current_amount = next_amount


    def process_message(self):
        """
        Process a message containing forex quotes from the message queue. Update the graph with the new quotes and remove stale quotes if necessary.
        """

        quotes = self.message_queue.get() #block until new quotes are given
        
 
        
        #parse throught the quotes
        for quote in quotes:
            currency1 = quote['currency1']
            currency2 = quote['currency2']
            rate = quote['rate']
            timestamp = quote['timestamp']
                            
            print(f"{timestamp} {currency1} {currency2} {rate}")

            #if this is an actually new quote not an old quote, then update the graph
            if self.latest_timestamps.get((currency1, currency2), datetime.min) < timestamp:
                
                
                #update the latest timestamp for this currency pair to check for stale quotes later
                self.latest_timestamps[(currency1, currency2)] = timestamp
                self.latest_timestamps[(currency2, currency1)] = timestamp
                
                #update graph edges with the new exchange rate
                self.graph.add_edge(currency1, currency2, -math.log10(rate))
                self.graph.add_edge(currency2, currency1, math.log10(rate)) #reciprocal
            else:
                print('ignoring out-of-sequence message')


        #check for stale quotes and remove them.
        current_time = datetime.utcnow()
        for (currency1, currency2), last_time in list(self.latest_timestamps.items()): 
            if current_time - last_time > self.VALIDITY_PERIOD: #check if the quote is stale
                
                #if the quote is stale, remove it from the graph and the latest_timestamps
                self.graph.remove_edge(currency1, currency2)
                del self.latest_timestamps[(currency1, currency2)]
                print(f"Removing stale quote for {currency1}/{currency2}")
    
        
        

    def run(self):
        """
        Start the ArbitrageDetector by subscribing to the forex provider, starting the listener thread and always processing new messages and checking for arbitrage opportunities. 
        """
        #subscribe to forex provider
        self.subscribe_to_forex_provider()
        
        #start the listener thread
        threading.Thread(target=self.listener_thread, daemon=True).start()
        
        while True:
            #process the message
            self.process_message()

            self.check_arbitrage()

        

if __name__ == "__main__":
    """
    Main function to run the ArbitrageDetector. Takes the forex provider address as command line arguments.
    """
    if len(sys.argv) != 3:
        print("Format: python lab3.py [provider_host] [provider_port]")
        exit(1)
    address = (sys.argv[1], int(sys.argv[2]))
    subscriber = ArbitrageDetector(address)
    subscriber.run()

