import dpkt
import struct

class Flow:

    


def test():
    f = open('assignment2.pcap', 'rb')
    pcap =  dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        print(ts)
        print(buf)
        print(len(buf))

        tcp_header = buf[34:54]

        result = struct.unpack_from("!HHIIBB", tcp_header)

        source_port = result[0]
        dest_port = result[1]
        seq_num = result[2]
        ack_num = result[3]
        unused = result[4]
        flags = result[5]
        flags = (flags << 2) >> 2


        print(source_port)
        print(dest_port)
        print(seq_num)
        print(ack_num)
        print(flags)

        if flags == 2:
            print("SYN")
        elif flags == 16:
            print("ACK")
        elif flags == 17:
            print("FIN ACK")
        elif flags == 18:
            print("SYN ACK")
        elif flags == 24:
            print("PSH ACK")


        # result = struct.unpack("14c52c", buf)
        # print(result)

if __name__ == "__main__":
    test()