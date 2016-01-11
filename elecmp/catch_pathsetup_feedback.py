import SocketServer

def print_data(s):
    data= list(map(ord, s))
    if len(data) < 14:
        print data
        return
    print '5 tuple info'
    print '<the_protocol>: {0}'.format(data[8])
    print '<src_ip, port>: {0}.{1}.{2}.{3}, {4}'.format(data[0], data[1], data[2], data[3], (data[ 9]<<8) + data[10])
    print '<dst_ip, port>: {0}.{1}.{2}.{3}, {4}'.format(data[4], data[5], data[6], data[7], (data[11]<<8) + data[12])
    lst = data[13:]
    #nhop_id_list = [(lst[2*i]<<3) + lst[2*i+1] for i in range(len(lst)//2)]
    print '<nhop_id_list>: {0}'.format(lst)
    print ""


class MyUDPHandler(SocketServer.BaseRequestHandler):
    """
    This class works similar to the TCP handler class, except that
    self.request consists of a pair of data and client socket, and since
    there is no connection the client address must be given explicitly
    when sending data back via sendto().
    """

    def handle(self):
        data = self.request[0]
        socket = self.request[1]
        print "{} wrote:".format(self.client_address[0])
        print_data(data)
        #print map(ord, data)
        #socket.sendto(data.upper(), self.client_address)

if __name__ == "__main__":
    HOST, PORT = "10.0.0.1", 4
    server = SocketServer.UDPServer((HOST, PORT), MyUDPHandler)
    print "start...."
    server.serve_forever()
