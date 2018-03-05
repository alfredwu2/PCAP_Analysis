import dpkt
import struct

class Flow:

    def __init__(self, sender_port, receiver_port):
        self.sender_port = sender_port
        self.receiver_port = receiver_port

        self.handshake_stage = 1
        self.data_sent = 0
        self.unacked_packets = set()
        self.lost_packets = 0
        self.total_packets = 0

    def sent(self, seq_num):
        self.total_packets += 1
        if seq_num in self.unacked_packets:
            self.lost_packets += 1
        self.unacked_packets.add(seq_num)

    def acked(self, ack_num):
        for num in self.unacked_packets:
            if num < ack_num:
                self.unacked_packets.discard(num)

    def match(self, source_port, dest_port):
        if self.sender_port == source_port or self.sender_port == dest_port:
            return True
        else:
            return False

    def is_sender(self, source_port):
        if self.sender_port == source_port:
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

        # identify or create flow
        if flags == 2:
            new_flow = Flow(sender_port=source_port, receiver_port=dest_port)
            flows.append(new_flow)
            current_flow = new_flow
            # TODO calculate end of TCP 3-way handshake
        else:
            for flow in flows:
                if flow.match(source_port=source_port, dest_port=dest_port):
                    current_flow = flow
                    break

        # etc
        if current_flow.handshake_stage == 1 and current_flow.sender_port != source_port and flags == 18: # SYN ACK
            current_flow.handshake_stage = 2

        if current_flow.handshake_stage == 2 and current_flow.sender_port == source_port and flags == 16: # ACK
            current_flow.handshake_stage = 3

        elif current_flow.handshake_stage == 3:
            if current_flow.is_sender(source_port=source_port):
                current_flow.sent(seq_num=seq_num)

        print(ts)

        # print(current_flow.unacked_packets)
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

    for flow in flows:
        print("%d / %d" % (flow.lost_packets, flow.total_packets))

if __name__ == "__main__":
    test()