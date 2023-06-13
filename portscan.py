#! /usr/bin/python

import sys
import logging
from scapy.layers.inet import *
import threading

logging.getLogger("scapy.runtime").setLevel(logging.ERROR)  # This is supress scapy warnings
conf.verb = 0
conf.nofilter = 1
global verbose_mode


class Port:
    def __init__(self, type, port):
        self.type = type
        self.port = port


def syn_tcp_is_open(ip, port, timeout):
    src_port = RandShort()
    result = sr1(IP(dst=ip) / TCP(sport=src_port, dport=port, flags="S"), timeout=timeout)
    if result is None:
        return False, -1
    elif result.haslayer(TCP) and result.getlayer(TCP).flags == 0x12:
        return True, result.time
    else:
        return False, -1


def udp_is_open(ip, port, timeout):
    result = sr1(IP(dst=ip) / UDP(dport=port), timeout=timeout)
    if result is None:
        return False, -1
    elif result.haslayer(UDP):
        return True, result.time
    else:
        return False, -1


def start(ip, ports, timeout):
    global verbose_mode

    for port in ports:
        if port.type == 'UDP':
            is_open, tm = udp_is_open(ip, port.port, timeout)
        else:
            is_open, tm = syn_tcp_is_open(ip, port.port, timeout)

        if is_open and verbose_mode and port.type == 'TCP':
            print(f"{port.type} {port.port} {tm}")
        elif is_open:
            print(f"{port.type} {port.port}")


def main():
    global verbose_mode
    OPTIONS = [i for i in sys.argv if '-' in i]

    timeout_options = [i for i in OPTIONS if '--timeout' in i]
    timeout = 2

    if len(timeout_options) == 1:
        t_opt = timeout_options[0]
        timeout = int(t_opt.split('=')[1])

    vm_options = [i for i in OPTIONS if '--verbose' in i or '-v' in i]
    if len(vm_options) == 1:
        verbose_mode = True
    else:
        verbose_mode = False

    IND_IP = 1
    for i in range(len(sys.argv[1:])):
        ind = i + 1
        if '-' not in sys.argv[ind]:
            IND_IP = int(ind)
            break
    ip = sys.argv[IND_IP]

    PORTS = []

    for x in sys.argv[IND_IP+1:]:
        type_connect, input_ports = x.split('/')[0], x.split('/')[1]
        if ',' in input_ports:
            ports = [int(i) for i in input_ports.split(',')]
            if type_connect == 'tcp':
                PORTS += [Port('TCP', i) for i in ports]
            elif type_connect == 'udp':
                PORTS += [Port('UDP', i) for i in ports]
        elif '-' in input_ports:
            start_port, end_port = int(input_ports.split('-')[0]), int(input_ports.split('-')[1])
            if type_connect == 'tcp':
                for i in range(start_port, end_port + 1):
                    PORTS.append(Port('TCP', i))
            elif type_connect == 'udp':
                for i in range(start_port, end_port + 1):
                    PORTS.append(Port('UDP', i))
        else:
            if type_connect == 'tcp':
                PORTS.append(Port('TCP', int(input_ports)))
            elif type_connect == 'udp':
                PORTS.append(Port('UDP', int(input_ports)))

    num_threads_options = [i for i in OPTIONS if '--num-threads' in i or '-j' in i]
    num_threads = 1

    if len(num_threads_options) == 1:
        t_opt = num_threads_options[0]
        num_threads = int(t_opt.split('=')[1])

    count_ports_in_thread = int(len(PORTS) / num_threads)

    first_port = 0
    for i in range(num_threads - 1):
        threading.Thread(target=start, args=(ip, PORTS[first_port:first_port+count_ports_in_thread], timeout)).start()
        first_port = (i + 1) * count_ports_in_thread
    threading.Thread(target=start, args=(ip, PORTS[first_port:], timeout)).start()


if __name__ == "__main__":
    main()
