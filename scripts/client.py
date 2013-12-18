import zmq

class ObserverClient(object):
    def __init__(self):
        """
        Initialize the context and socket of ZMQ
        """
        self.context = zmq.Context()
        self.socket = self.context.socket(zmq.REQ)

    def connect(self, host):
        """
        Connect to the remote endpoint.
        """
        #  Socket to talk to server
        print "Connecting to %s server..." % host
        self.socket.connect ("tcp://%s:4141" % host)
        
    def message(self, message):
        """
        Send a message to the endpoint.
        """
        self.socket.send (message)    
        message = self.socket.recv()
        
        return message
        
import sys
import struct

if __name__ == '__main__':
    client = ObserverClient()
    client.connect("localhost")
    response = client.message(struct.pack("<L", 0xe895000c))
    
    if response == "ERROR":
        print "Got an error from the server"
        sys.exit()
        
    print "Execution was sucessful"
        
    # first line is pre execution context, second line is post execution context
    context = filter(None, response.split("\n"))
    pre_context = filter(None, context[0].split(",")) 
    post_context = filter(None, context[1].split(","))
    signal = context[2]
    
    print "Instruction executed with signal: ", signal
    
    print "Pre-execution context:"
    print pre_context
    
    print "Post-execution context:"
    print post_context

    print "Signal:"
    print signal
        
    print "Memory accesses:"
    for a in context[3:]:
        print a