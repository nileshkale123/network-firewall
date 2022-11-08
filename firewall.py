from struct import *
import socket, struct, time, os, binascii
import click, select, json
import matplotlib.pyplot as plt
from getkey import getkey


class bcol:
    SERVER_col = "\033[95m"  # LightMagenta
    CLIENT_col = "\033[94m"  # LightYellow
    OKBLUE = "\033[94m"
    OKCYAN = "\033[96m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"  # LigntRed
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    UNDERLINE = "\033[4m"


def clean() -> None:
    os.system("cls" if os.name == "nt" else "clear")


class SimpleFirewall:
    def __init__(self, interface1, interface2):
        self.internal_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))
        self.external_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        self.internal_socket.bind((interface1, 0))
        self.external_socket.bind((interface2, 0))

        self.internal_host_mac = "52:54:00:f7:69:35"
        self.external_host_mac = "52:54:00:d6:10:87"

        self.rules = {"BLOCKED_IP_LIST": ["142.250.182.46"]}

    def get_ip(self, addr):
        return ".".join(map(str, addr))

    def parse_ethernet(self, raw_data):
        dest, src, prototype = struct.unpack("!6s6sH", raw_data[:14])
        destin_mac_addr = ":".join("%02x" % b for b in dest)
        src_mac_addr = ":".join("%02x" % b for b in src)
        prototype_field = socket.htons(prototype)
        return destin_mac_addr, src_mac_addr, prototype_field

    def parse_IP(self, raw_data):
        version_header_length = raw_data[0]
        version = version_header_length >> 4
        header_length = (version_header_length & 15) * 4
        ttl, proto, src, target = struct.unpack("! 8x B B 2x 4s 4s", raw_data[:20])
        data = raw_data[header_length:]
        src = self.get_ip(src)
        target = self.get_ip(target)
        return version, header_length, ttl, proto, src, target, data

    def parse_rules(self, raw_data):
        eth = self.parse_ethernet(raw_data)
        ip = self.parse_IP(raw_data[14:])

        if eth[1] == self.external_host_mac:
            # ip[4] == Source IPV4 Address
            if ip[4] in self.rules["BLOCKED_IP_LIST"]:
                allow = False
            else:
                allow = True
                dest_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])
                dest_mac = binascii.unhexlify(self.internal_host_mac.replace(":", ""))
                new_data = struct.pack("! 6s 6s H", dest_mac, src_mac, type_mac) + raw_data[14:]
                self.internal_socket.sendall(new_data)

        elif eth[1] == self.internal_host_mac:
            allow = True
            dest_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])
            dest_mac = binascii.unhexlify(self.external_host_mac.replace(":", ""))
            new_data = struct.pack("! 6s 6s H", dest_mac, src_mac, type_mac) + raw_data[14:]
            self.external_socket.sendall(new_data)
        else:
            allow = False

        return allow, ip[4]

    def run(self):
        while True:
            all_socks = [self.internal_socket, self.external_socket]
            ready_socks, _, _ = select.select(all_socks, [], [])

            for soc in ready_socks:
                raw_data, _ = soc.recvfrom(65565)
                ret, ip = self.parse_rules(raw_data)
                if ret:
                    print(f"{ip}: Allowed")
                else:
                    print(f"{ip}: Dropped")


class Firewall:
    def __init__(self, interface1, interface2, dos_threshold: int = 100, mapper_file: str = "mapper.json"):
        """Advanced Firewall Class

        Args:
            interface1 (Socket): Interface that is connected in to one subnet
            interface2 (Socket): Interface that is connected to next subnet
            dos_threshold (int, optional): Number of packets before firewall detects DDoS. Defaults to 0.
            mapper_file (str, optional): File that accumulates all the informations from raw sockets. Defaults to "mapper.json".
        """

        self.internal_socket, self.external_socket = self.initialize_socket(interface1, interface2)

        self.rules_set = {}
        self.mapping_dict = self.load_mapper(mapper_file)
        self.packet = ""
        self.times = []

        self.dos_threshold = dos_threshold
        self.sources_ipv4 = {}

        self.mean_time = 0.0
        self.plot_allow, self.plot_discard = [], []
        self.allowed, self.discarded = 0, 0

    def load_mapper(self, mapper_file: str):
        """File to load the elements to capture from the raw sockets

        Args:
            mapper_file (str, optional): File that accumulates all the informations from raw sockets. Defaults to "mapper.json".

        Returns:
            _type_: dictionary
        """
        with open(mapper_file, "r") as handler:
            mapper = json.load(handler)
        return mapper

    def initialize_socket(self, interface1, interface2):
        """Function to initialize the sockets

        Args:
            interface1 (Socket): First Network
            interface2 (Socket): Next Network

        Returns:
            socket, socket: Binded Sockets for both the networks
        """

        internal_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x003))
        external_socket = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(0x0003))

        internal_socket.bind((interface1, 0))
        external_socket.bind((interface2, 0))

        return internal_socket, external_socket

    def parse_L2(self, raw_data: str, byte_len: int = 14):
        """Parsing the information of the L2 Layers

        Args:
            raw_data (str): Taking the raw data from the socket
            byte_len (int, optional): Number of bytes for L2 Layer. Defaults to 14.
        """

        self.packet = f"{bcol.OKBLUE}[Ethernet]{bcol.ENDC}"

        destination, source, prototype = struct.unpack("!6s6sH", raw_data[:byte_len])
        dstn_mac = ":".join("%02x" % m for m in destination)
        src_mac = ":".join("%02x" % s for s in source)

        ethprotocol = socket.htons(prototype)

        self.mapping_dict["dstn_mac"] = dstn_mac
        self.mapping_dict["src_mac"] = src_mac
        self.mapping_dict["etherprotocol"] = ethprotocol
        if ethprotocol == socket.ntohs(0x0800):
            self.parse_IP_headers(raw_data[14:])

    def parse_L3(self, raw_data: str):

        self.packet += f"{bcol.OKBLUE}[IPv4]{bcol.ENDC}"

        iph = unpack("!BBHHHBBH4s4s", raw_data[:20])

        version_len = iph[0]

        ihl = version_len & 0xF
        ihl_len = ihl * 4

        ipv4protocol = iph[6]

        source_addr = socket.inet_ntoa(iph[8])
        dest_addr = socket.inet_ntoa(iph[9])

        self.mapping_dict["header_len"] = ihl_len
        self.mapping_dict["ttl"] = iph[5]
        self.mapping_dict["ipv4protocol"] = ipv4protocol
        self.mapping_dict["src_ip"] = source_addr
        self.mapping_dict["dstn_ip"] = dest_addr

        if ipv4protocol == 1:
            self.parse_L3_ICMP(raw_data[ihl_len:])

        elif ipv4protocol == 6:
            self.parse_L3_TCP(raw_data[ihl_len:])

        elif ipv4protocol == 17:
            self.parse_L3_UDP(raw_data[ihl_len:])

    def parseIPv6Head(self, raw_data):
        self.packet += "\u001b[43;1m[IPv6]\u001b[0m"
        iph = struct.unpack("!HHHHHH16s16s", raw_data[:20])

        traffic_class = iph[5]
        flow_label = iph[6]
        header_len = iph[7]
        ipv6protocol = iph[8]
        v6source_addr = ":".join("%0x{0:X2}" % b for b in iph[9])
        v6dest_addr = ":".join("%0x{0:X2}" % b for b in iph[10])

        self.mapping_dict["traffic_class"] = traffic_class
        self.mapping_dict["flow_label"] = flow_label
        self.mapping_dict["ipv4_header_len"] = header_len
        self.mapping_dict["ipv6protocol"] = ipv6protocol
        self.mapping_dict["v6source_addr"] = v6source_addr
        self.mapping_dict["v6dest_addr"] = v6dest_addr

        if ipv6protocol == 1:
            self.parseICMPv6Head(raw_data[header_len:])

        elif ipv6protocol == 6:
            self.parse_L3_TCP(raw_data[header_len:])

        elif ipv6protocol == 17:
            self.parse_L3_UDP(raw_data[header_len:])

    def parse_IP_headers(self, raw_data):
        version_len = raw_data[0]

        version = version_len >> 4

        if version == 4:
            self.parse_L3(raw_data)
        else:
            self.parseIPv6Head(raw_data)

    def parse_L3_ICMP(self, raw_data):
        self.packet += f"{bcol.OKBLUE}[ICMPv4]{bcol.ENDC}"

        typ, code, _, _, _ = struct.unpack("!bbHHh", raw_data[:8])
        self.mapping_dict["icmp4type"] = typ
        self.mapping_dict["icmp4code"] = code

    def parseICMPv6Head(self, raw_data):
        self.packet += f"{bcol.OKBLUE}ICMPv6{bcol.ENDC}"
        typ, code, _ = struct.unpack("!bbH", raw_data[:4])

        self.mapping_dict["icmp6type"] = typ
        self.mapping_dict["icmp6code"] = code

    def parse_L3_TCP(self, raw_data):
        self.packet += f"{bcol.OKBLUE}[TCP]{bcol.ENDC}"
        (tcpsrc_port, tcpdest_port, _, _, offset) = struct.unpack("!HHLLH", raw_data[:14])

        urg = (offset & 32) >> 5
        ack = (offset & 16) >> 4
        rst = (offset & 4) >> 2
        syn = (offset & 2) >> 1
        fin = offset & 1

        self.mapping_dict["tcpsrc_port"] = tcpsrc_port
        self.mapping_dict["tcpdest_port"] = tcpdest_port

        self.mapping_dict["flag_urg"] = urg
        self.mapping_dict["flag_ack"] = ack
        self.mapping_dict["flag_rst"] = rst
        self.mapping_dict["flag_syn"] = syn
        self.mapping_dict["flag_fin"] = fin

    def parse_L3_UDP(self, raw_data):
        self.packet += "\u001b[47;1m\u001b[30;1m[UDP]\u001b[0m\u001b[0m"
        pack = struct.unpack("!4H", raw_data[:8])

        self.mapping_dict["udpsrc_port"] = pack[0]
        self.mapping_dict["udpdest_port"] = pack[1]
        self.mapping_dict["udpdata_len"] = pack[2]

    def manageRules(self):
        try:
            if os.path.exists("rules.json") == False:
                rules_template = {"L2": [], "L3v4": [], "L3v6": [], "L4TCP": [], "L4UDP": [], "ICMP": []}
                with open("rules.json", "w") as outfile:
                    json.dump(rules_template, outfile)
            os.system("sudo gedit rules.json")

        except KeyboardInterrupt as e:

            self.load_rules()
            clean()
            main()

    def parse_rules(self, raw_data):

        start = time.process_time()
        self.parse_L2(raw_data)
        allowed = False

        acceptance = []
        for layer in self.rules_set.keys():
            for rule in self.rules_set[layer]:
                for key in rule.keys():
                    if key != "rule_id" and key != "rule":
                        print(rule[key], self.mapping_dict[key])
                        if rule[key] == self.mapping_dict[key]:
                            acceptance.append(True)
                        else:
                            acceptance.append(False)
                if all(acceptance) == True:
                    if rule["rule"].lower() == "allow":
                        allowed = True
                    else:
                        allowed = False

        if self.mapping_dict["src_ip"] in self.sources_ipv4:
            self.sources_ipv4[self.mapping_dict["src_ip"]] += 1
        else:
            self.sources_ipv4[self.mapping_dict["src_ip"]] = 0

        if self.sources_ipv4[self.mapping_dict["src_ip"]] > self.dos_threshold:
            print("\u001b[41;1m DoS Detected\u001b[0m")
            allowed = False

        end = time.process_time() - start
        return allowed, end

    def run(self, internal_MAC, external_MAC):

        clock = time.time()

        while True:
            try:

                all_socks = [self.internal_socket, self.external_socket]
                ready_socks, _, _ = select.select(all_socks, [], [])

                for soc in ready_socks:

                    if time.time() - clock >= 1:
                        self.plot_allow.append(self.allowed)
                        self.plot_discard.append(self.discarded)
                        clock = time.time()

                    raw_data, _ = soc.recvfrom(65565)

                    status, ppt = self.parse_rules(raw_data)

                    self.times.append(ppt)
                    self.mean_time = sum(self.times) / len(self.times)

                    if status == True:
                        self.allowed += 1
                        self.discarded += 0

                        if self.mapping_dict["src_mac"] == internal_MAC:

                            dstn_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])
                            dstn_mac = binascii.unhexlify(external_MAC.replace(":", ""))
                            new_data = struct.pack("! 6s 6s H", dstn_mac, src_mac, type_mac) + raw_data[14:]
                            self.external_socket.sendall(new_data)

                        elif self.mapping_dict["src_mac"] == external_MAC:

                            dstn_mac, src_mac, type_mac = struct.unpack("! 6s 6s H", raw_data[:14])
                            dstn_mac = binascii.unhexlify(internal_MAC.replace(":", ""))
                            new_data = struct.pack("! 6s 6s H", dstn_mac, src_mac, type_mac) + raw_data[14:]
                            self.internal_socket.sendall(new_data)
                        print(
                            f"""{self.packet} \n"""
                            f"""[Src MAC]: {bcol.BOLD}{self.mapping_dict["src_mac"]}{bcol.ENDC}, [Dstn MAC]: {bcol.BOLD}{self.mapping_dict["dstn_mac"]}{bcol.ENDC} \n"""
                            f"""[Src IP]: {bcol.BOLD}{self.mapping_dict["src_ip"]}{bcol.ENDC}, [Dstn IP]: {bcol.BOLD}{self.mapping_dict["dstn_ip"]}{bcol.ENDC} \n"""
                            f"""[Status]: \u001b[42;1mAllowed\u001b[0m \n"""
                            f"""[PPT] : {round(ppt, 8)}\n\n"""
                        )

                    else:
                        self.allowed += 0
                        self.discarded += 1
                        print(
                            f"""{self.packet}\n"""
                            f"""[Src MAC]: {bcol.BOLD}{self.mapping_dict["src_mac"]}{bcol.ENDC}, [Dstn MAC]: {bcol.BOLD}{self.mapping_dict["dstn_mac"]}{bcol.ENDC} \n"""
                            f"""[SrcIP]: {bcol.BOLD}{self.mapping_dict["src_ip"]}{bcol.ENDC}, [Dstn IP]: {bcol.BOLD}{self.mapping_dict["dstn_ip"]}{bcol.ENDC} \n"""
                            f"""[Status]: {bcol.FAIL}{"Dropped"}{bcol.ENDC} \n"""
                            f"""[PPT] : {round(ppt, 8)}\n\n"""
                        )

            except KeyboardInterrupt as e:
                clean()
                self.analyse_capture()
                i = True
                print("Press 'c' to continue...")

                while i:
                    key = getkey()
                    if key == "c":
                        i = False
                main()

    def analyse_capture(self):

        print("Firewall Capture Statistics\n")
        print("Mean Packet Processing Time : ", self.mean_time, "\n")
        print("No of packets allowed : ", self.allowed, "\n")
        print("No of packets dropped : ", self.discarded, "\n")
        print(f"No of rules in system : {sum(len(v) for v in self.rules_set.values())}")

        plt.title("Firewall Statistics")

        plt.plot(range(len(self.plot_allow)), self.plot_allow, label="Allowed pkts")
        plt.plot(range(len(self.plot_discard)), self.plot_discard, label="Dropped Pkts")

        plt.xlabel("Running Time")
        plt.ylabel("Number of allowed/dropped packets")
        plt.grid()
        plt.legend(["Allowed Packets", "Dropped Packets"])
        plt.savefig("firewall_statistics.png")

    def load_rules(self):
        with open("rules.json", "r") as infile:
            self.rules_set = json.load(infile)

    def set_dos_threshold(self, dos_threshold):
        self.check_dos = True
        self.dos_threshold = dos_threshold


@click.command()
@click.option("-d", help="DDos Attack Detection", default=100)
@click.option("-s", help="Simple Firewall", default=False, is_flag=True)
def main(d, s):
    interface1 = "enp1s0"
    interface2 = "enp6s0"

    if s:
        simple_firewall = SimpleFirewall(interface1, interface2)
        simple_firewall.run()
    else:

        firewall = Firewall(interface1, interface2, d)
        clean()
        while True:

            print("\nStart Firewall with 's', Manage Rules with 'r', Exit with 'e' \n\n")
            key = getkey()
            if key == "s":
                try:
                    firewall.load_rules()
                except FileNotFoundError:
                    pass
                clean()
                firewall.run(internal_MAC="52:54:00:f7:69:35", external_MAC="52:54:00:d6:10:87")

            if key == "r":
                try:
                    firewall.load_rules()
                except FileNotFoundError:
                    pass
                firewall.manageRules()

            if key == "e":
                clean()
                exit(0)


if __name__ == "__main__":
    main()
