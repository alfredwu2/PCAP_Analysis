import dpkt
import struct
import math

class Packet:

    def __init__(self, seq_num, payload):
        self.seq_num = seq_num
        self.payload = payload


class Flow:

    def __init__(self, sender_port, receiver_port, starttime):
        self.sender_port = sender_port
        self.receiver_port = receiver_port

        self.handshake_stage = 1
        self.data_sent = 0
        self.unacked_packets = set()
        self.lost_packets = 0
        self.total_packets = 0
        self.sent_time = {}
        self.rtt_estimate = 0
        self.alpha = 0.125
        self.starttime = starttime

        self.consecutive = 0
        self.cwindows = []
        self.ack_count = {}

        self.triple_dupes = 0

    def throughput(self):
        return self.data_sent / (self.endtime - self.starttime)

    def sent(self, seq_num, payload, ts, size):

        self.consecutive += 1

        self.total_packets += 1
        self.data_sent += size

        self.sent_time[seq_num] = ts

        for packet in self.unacked_packets:
            if packet.seq_num == seq_num:
                self.lost_packets += 1

                if self.ack_count[seq_num] >= 3:
                    self.triple_dupes += 1
                return

        packet = Packet(seq_num=seq_num, payload=payload)
        self.unacked_packets.add(packet)

    def acked(self, ack_num, ts):

        if ack_num in self.ack_count:
            self.ack_count[ack_num] += 1
        else:
            self.ack_count[ack_num] = 1


        if len(self.cwindows) < 10 and self.consecutive > 0:
            # self.cwindows.append(self.consecutive)
            self.cwindows.append(len(self.unacked_packets))
        self.consecutive = 0

        acked_packets = []

        for packet in self.unacked_packets:
            if packet.seq_num + packet.payload < ack_num:
                acked_packets.append(packet)

                if packet.seq_num + packet.payload == ack_num - 1:
                    rtt = ts - self.sent_time[packet.seq_num]
                    self.rtt_estimate = self.rtt_estimate * self.alpha + (1 - self.alpha) * rtt



        for packet in acked_packets:
            self.unacked_packets.discard(packet)


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

        result = struct.unpack_from("!HHIIBBH", tcp_header)

        source_port = result[0]
        dest_port = result[1]
        seq_num = result[2]
        ack_num = result[3]
        offset = result[4]
        offset = (offset >> 4)
        flags = result[5]
        flags = (flags << 2) >> 2
        window = result[6]

        payload = len(buf[34:]) - offset * 4

        # identify or create flow
        if flags == 2:
            new_flow = Flow(sender_port=source_port, receiver_port=dest_port, starttime=ts)
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

        elif current_flow.handshake_stage == 2 and current_flow.sender_port == source_port and flags == 16: # ACK
            current_flow.handshake_stage = 3

        elif current_flow.handshake_stage >= 3:
            if current_flow.is_sender(source_port=source_port):
                current_flow.sent(seq_num=seq_num, payload=payload, ts=ts, size=len(buf))

                if current_flow.handshake_stage == 3:
                    current_flow.first_seq = seq_num
                    current_flow.first_ack = seq_num + payload + 1
                    current_flow.first_window = window
                    current_flow.handshake_stage = 4

                elif current_flow.handshake_stage == 4:
                    current_flow.second_seq = seq_num
                    current_flow.second_ack = seq_num + payload + 1
                    current_flow.second_window = window
                    current_flow.handshake_stage = 5

            else:
                pass
                current_flow.acked(ack_num=ack_num, ts=ts)

        current_flow.endtime = ts



        # print(current_flow.unacked_packets)

        # count += 1
        # if count == 10:
        #     break

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
        print("Flow from sender port %s" % flow.sender_port)

        print("First transaction sequence number: %d" % flow.first_seq)
        print("First transaction ack number: %d" % flow.first_ack)
        print("First transaction receive window: %d" % flow.first_window)

        print("Second transaction sequence number: %d" % flow.second_seq)
        print("Second transaction ack number: %d" % flow.second_ack)
        print("Second transaction receive window: %d" % flow.second_window)

        count = 1
        for window in flow.cwindows:
            print("Congestion window %d: %d" % (count, window))
            count += 1

        p = flow.lost_packets / flow.total_packets
        print("Packets lost: %d / %d = %f" % (flow.lost_packets, flow.total_packets, p))
        print("RTT: %f seconds" % (flow.rtt_estimate))
        print("Empirical throughput: %d bytes per second" % flow.throughput())

        print("Packets retransmitted due to triple duplicate ACKs: %d" % flow.triple_dupes)
        print("Packets retransmitted due to timeout: %d" % (flow.lost_packets - flow.triple_dupes))

        if p == 0:
            print("Theoretical throughput: undefined")
        else:
            theoretical_throughput = (math.sqrt(1.5) * 1460) / (flow.rtt_estimate * math.sqrt(p))
            print("Theoretical throughput: %d bytes per second" % theoretical_throughput)

        print("test")
        print("\n")

if __name__ == "__main__":
    test()