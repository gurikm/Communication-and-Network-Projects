import argparse
import sys
import dpkt
import socket

#---------------------------------------------------------Connect-Class--------------------------------------------------------------------#
class Connect():
    def __init__(self, src_ip, src_port, dst_ip, dst_port):
        self.src_ip = src_ip
        self.src_port = src_port
        self.dst_ip = dst_ip
        self.dst_port = dst_port
        self.rst = 0
        self.fin = 0
        self.syn = 0
        self.packets = [0,0]
        self.bytes = [0,0]
        self.start_time = None
        self.end_time = None
        self.window_size = [0,0]
        self.rtt = []

    def __eq__(self, other):
        if (self.src_ip == other.src_ip and self.src_port == other.src_port and self.dst_ip == other.dst_ip and self.dst_port == other.dst_port): 
            return True
        if (self.src_ip == other.dst_ip and self.src_port == other.dst_port and self.dst_ip == other.src_ip and self.dst_port == other.src_port):
            return True
        return False

    def get_rst(self):
        return self.rst
    def is_complete(self):
        return self.syn and self.fin
    def get_num_packets(self):
        return sum(self.packets)
    def get_win(self):
        return self.window_size
    def add_rtt(self, rtt):
        self.rtt.append(rtt)
    def get_rtt(self):
        return self.rtt
#---------------------------------------------------------Connect-Class--------------------------------------------------------------------#
def add_connections(pcap):
    connections = []
    rtt = {}
    for ts, buf in pcap:
        ip = dpkt.ethernet.Ethernet(buf).data
        src_ip = socket.inet_ntoa(ip.src)
        dest_ip = socket.inet_ntoa(ip.dst)
        connector = Connect(src_ip, ip.data.sport, dest_ip, ip.data.dport)
        try:
            i = connections.index(connector)
        except ValueError:
            connections.append(connector)
        i = connections.index(connector)

        if ip.data.flags & 4 == 4:
            connections[i].rst = 1

        if ip.data.flags & 2 == 2:
            connections[i].syn += 1
            if connections[i].syn == 1:
                connections[i].start_time = ts

        if ip.data.flags & 1 == 1:
            connections[i].fin += 1
            connections[i].end_time = ts

        if src_ip == connections[i].src_ip and dest_ip == connections[i].dst_ip:
            connections[i].packets[0] += 1
            connections[i].bytes[0] += len(ip.data.data)
            connections[i].window_size[0] = ip.data.win
        else:
            connections[i].packets[1] += 1
            connections[i].bytes[1] += len(ip.data.data)
            connections[i].window_size[1] = ip.data.win

        rtt[ip.data.seq + len(ip.data.data)] = ts
        if ip.data.ack in rtt: 
            connections[i].add_rtt(ts - rtt[ip.data.ack])
    return connections

def analyze_connections(connections): #done
    mean_duration = 0
    max_duration = 0
    min_duration = 0
    inital_time = 1139256717.834392
    complete = []
    wins=[]
    for connector in connections:
       if connector.is_complete():
           complete.append(connector)
    reset = 0
    for connector in connections:
        if connector.get_rst():
            reset += 1
    TCP_complete = len(complete)

    for i, connector in enumerate(connections):
        if connector.syn > 0 and connector.fin > 0:
            if connector.start_time and connector.end_time:
                duration = connector.end_time - connector.start_time
            #mean_duration
            mean_duration += duration
            #max duration
            if duration > max_duration:
               max_duration = duration
            #min_duration
            if min_duration == 0:
                min_duration = duration
            elif duration < min_duration:
                min_duration = duration
    windows = []
    for connector in connections:
        windows += connector.get_win()
    min_window_size = min(windows)
    mean_window_size = (sum(windows)/len(connections))
    max_window_size = max(windows)

    rtts = []
    for connector in complete:
        rtts += connector.get_rtt()
    min_rtt = min(rtts)
    mean_rtt = sum(rtts)/len(rtts)
    max_rtt = max(rtts)

    packets = []
    for connector in complete:
        packets.append(connector.get_num_packets())
    min_packet =  min(packets)
    mean_packet = (sum(packets)/len(connections))
    max_packet = max(packets)
#---------------------------------------------------------------Outputs------------------------------------------------------#
    print("A) Total number of connections:",len(connections))

    print("\n-------------------------------------------------------------------\n")

    print("B) Connections' details:\n")
    for i, connector in enumerate(connections):
        print("Connection " + str(i + 1) +":")
        print("Source Address:", connector.src_ip)
        print("Destination Address:", connector.dst_ip)
        print("Source Port:", connector.src_port)
        print("Destination Port:", connector.dst_port)
        print("Status: S{}F{}".format(connector.syn, connector.fin))
        #Only if the connection is complete provide the following information
        if connector.syn and connector.fin:
            print("Start Time: %.5f" % (connector.start_time - inital_time))
            print("End Time: %.5f" % (connector.end_time - inital_time))
            print("Duration: %.5f" % (connector.end_time - connector.start_time))
            print("Number of packets sent from Source to Destination: ", connector.packets[0])
            print("Number of packets sent from Destination to Source: ", connector.packets[1])
            print("Total number of packets: ", sum(connector.packets))
            print("Number of data bytes sent from Source to Destination: ", connector.bytes[0])
            print("Number of data bytes sent from Destination to Source ", connector.bytes[1])
            print("Total number of data bytes: ", sum(connector.bytes))
        print("END")
        if i < len(connections) - 1:
            print("\n+++++++++++++++++++++++++++++++++\n")

    print("\n-------------------------------------------------------------------\n")

    print("C) General:\n")
    print("Total number of complete TCP connections: {}".format(TCP_complete))
    print("Number of reset TCP connections: {}".format(reset))
    print("Number of TCP connections that were still open when the trace capture ended: {}\n".format(len(connections) - TCP_complete))

    print("\n-------------------------------------------------------------------\n")

    print("D) Complete TCP connections:\n")
    #Duration
    print("Minimum time duration: %.5f" % min_duration)
    print("Mean time duration: %.5f" % (mean_duration/TCP_complete))
    print("Maximum time duration: %.5f\n" % max_duration)
    #RTT
    print("Minimum RTT value: ", min_rtt)
    print("Mean RTT value: %.5f" % mean_rtt)
    print("Maximum RTT value: %.5f\n" % max_rtt)
    #Packets
    print("Minimum number of packets including both send/received: ", min_packet)
    print("Mean number of packets including both send/received: ", mean_packet)
    print("Maximum number of packets including both send/received: ", max_packet, "\n")
    #Window size
    print("Minimum receive window size including both send/received: ", min_window_size)
    print("Mean receive window size including both send/received: %.4f" % mean_window_size)
    print("Maximum receive window size including both send/received: ", max_window_size)

    print("\n-------------------------------------------------------------------\n")
    return
#---------------------------------------------------------------Outputs------------------------------------------------------#
def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('filename')
    args = parser.parse_args()
    filename = args.filename
    pcap = dpkt.pcap.Reader(open(filename, "rb"))
    connections = add_connections(pcap)
    analyze_connections(connections)
    open(filename, "rb").close()
    return

if __name__ == "__main__":
    main()

