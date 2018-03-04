import dpkt
import struct

class Packet:
    i = 10


def test():
    f = open('assignment2.pcap', 'rb')
    pcap =  dpkt.pcap.Reader(f)

    for ts, buf in pcap:
        print(ts)
        print(buf)
        print(len(buf))

        tcp_header = buf[34:54]

        result = struct.unpack_from("!HHI", tcp_header)

        source_port = result[0]
        dest_port = result[1]
        seq_num = result[2]


        print(source_port)
        print(dest_port)
        print(seq_num)

        break

        # result = struct.unpack("14c52c", buf)
        # print(result)

if __name__ == "__main__":
    test()