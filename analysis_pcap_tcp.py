import dpkt
import struct

class Flow:

    data_sent = 0
    unacked_packets = {}

    def __init__(self, sender_port, receiver_port):
        self.sender_port = sender_port
        self.receiver_port = receiver_port

    

    def match(self, source_port, dest_port):
        if self.sender_port == source_port or self.sender_port == dest_port:
            return True
        else:
            return False




def test():
    f = open('assignment2.pcap', 'rb')
    pcap =  dpkt.pcap.Reader(f)

    flows = []

    count = 0

    for ts, buf in pcap:
        # print(ts)
        # print(buf)
        # print(len(buf))

        tcp_header = buf[34:54]

        result = struct.unpack_from("!HHIIBB", tcp_header)

        source_port = result[0]
        dest_port = result[1]
        seq_num = result[2]
        ack_num = result[3]
        unused = result[4]
        flags = result[5]
        flags = (flags << 2) >> 2


        # print(source_port)
        # print(dest_port)
        # print(seq_num)
        # print(ack_num)
        # print(flags)

        if flags == 2:
            new_flow = Flow(sender_port=source_port, receiver_port=dest_port)
            flows.append(new_flow)
            current_flow = new_flow
        else:
            for flow in flows:
                if flow.match(source_port=source_port, dest_port=dest_port):
                    current_flow = flow
                    break






        count += 1
        if count == 10:
            break

        # elif flags == 16:
        #     print("ACK")
        # elif flags == 17:
        #     print("FIN ACK")
        # elif flags == 18:
        #     print("SYN ACK")
        # elif flags == 24:
        #     print("PSH ACK")


        # result = struct.unpack("14c52c", buf)
        # print(result)

if __name__ == "__main__":
    test()