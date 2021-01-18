################################################
# Developed by ghostsecurity | Nicholas Guirro #
# https://www.youtube.com/ghostsecurity        #
################################################

#!/usr/bin/python
# -*- coding: utf-8 -*-

import socket
import random
import ipaddress
import struct
import time
from threading import Thread
from argparse import ArgumentParser

# Argument parser 
parser = ArgumentParser(prog='icmp_scan',
                        usage='icmp_scan.py [options] [host], [-h] to help',
                        description='icmp scan for host discovery, privileges super user required!'
                        )

parser.add_argument('-t', '--time',metavar='', type=float, dest='time_ar', default=0.002, 
                    help='''
                    Use a float number to define the waiting time for sending each package 
                    (by default the number is 0.002) adjustment according to available band.
                    '''
                   )

parser.add_argument('-s', '--sm',metavar='' ,type=str,dest='submask',default='24', 
                    help='''
                    Put a network mask here to "randomize" the elements of the ip 
                    (mask set as standard, 24).
                    '''
                   )
parser.add_argument('-n','--namelist',metavar='', dest='namelist', type=str, default='log.txt', 
                    help='''
                    the name of the file to be saved with the hosts.
                    '''
                   )

parser.add_argument('host', type=str, 
                    help='''
                    Enter the ip address you want to perform the host discovery
                    (this argument is required).
                    '''
                   )

try:
    args = parser.parse_args()
except IOError, msg:
    parser.error(str(msg))

SIGNAL = True

# Check Packet integrity
def checksum(source_string):
    sum = 0
    count_to = (len(source_string) / 2) * 2
    count = 0
    while count < count_to:
        this_val = ord(source_string[count + 1]) * 256 + ord(source_string[count])
        sum = sum + this_val
        sum = sum & 0xffffffff
        count = count + 2
    if count_to < len(source_string):
        sum = sum + ord(source_string[len(source_string) - 1])
        sum = sum & 0xffffffff
    sum = (sum >> 16) + (sum & 0xffff)
    sum = sum + (sum >> 16)
    answer = ~sum
    answer = answer & 0xffff
    answer = answer >> 8 | (answer << 8 & 0xff00)
    return answer

# Create Packet 
def create_packet(id):
    header = struct.pack('bbHHh', 8, 0, 0, id, 1)
    data = 192 * 'Q'
    my_checksum = checksum(header + data)
    header = struct.pack('bbHHh', 8, 0, socket.htons(my_checksum), id, 1)
    return header + data

# Send all packets 
def ping(addr, timeout=1):
    try:
        ping_socket = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    except Exception as error:
        print error

    my_packet_id = int((id(timeout) * random.random()) % 65535)
    my_packet = create_packet(my_packet_id)
    ping_socket.connect((addr, 80))
    ping_socket.sendall((my_packet))
    ping_socket.close()

# Receive all packets 
def listen(responses):
    global SIGNAL
    s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
    s.bind(('', 666))
    print 'Listening...'
    while SIGNAL:
        recv_packet = s.recv(1024)[:20][-8:-4]
        responses.append(recv_packet)
    print 'Stop listening ...'
    s.close()

# ping, unpack funcion - save list, disable listen
def rotate(addr, file_name, wait, responses):
    print 'Sending Packets\n', time.strftime("%X %x %Z")
    for ip in addr:
        ping(str(ip))
        time.sleep(wait)
    print 'All packets send', time.strftime("%X %x %Z")
    print 'Waiting for all responses'
    time.sleep(4)
    global SIGNAL
    SIGNAL = False
    ping('127.0.0.1') #final ping to pass the signal = False and stop the listen function
    time.sleep(0.9)
    print len(responses), 'hosts found!'
    print "Writing File"
    hosts = []
    for response in sorted(responses):
        ip = struct.unpack('BBBB', response)
        ip = str(ip[0]) + "." + str(ip[1]) + "." + str(ip[2]) + "." + str(ip[3])
        hosts.append(ip)
    file = open(file_name, 'w')
    file.write(str(hosts))
    print "Done", time.strftime("%X %x %Z")

# main function
def main():
    responses =  []
    ips = (u'{}/{}'.format(args.host, args.submask))
    wait = args.time_ar # adjustment according to available band
    file_name = args.namelist
    ip_network = ipaddress.ip_network(ips, strict=False)


    t_server = Thread(target=listen, args=[responses])
    t_server.start()

    t_ping = Thread(target=rotate,args=[ip_network, file_name, wait, responses])
    t_ping.start()

main()

