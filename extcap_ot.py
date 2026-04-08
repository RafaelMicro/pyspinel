#!/usr/bin/env python3
#
#  Copyright (c) 2019, The OpenThread Authors.
#  All rights reserved.
#
import os
import sys
import tempfile
import argparse
import subprocess
import threading
import logging
import re

from spinel.stream import StreamOpen
from spinel.const import SPINEL
from spinel.codec import WpanApi
from serial.tools.list_ports import comports
from enum import Enum

# Nodeid is required to execute ot-ncp-ftd for its sim radio socket port.
DEFAULT_NODEID = 34
# Default baudrate scanning starts from 2,000,000 based on hardware requirements.
COMMON_BAUDRATE = [2000000, 115200, 9600]

class Config(Enum):
    CHANNEL = 0
    BAUDRATE = 1
    TAP = 2
    CHAN_MIN = 3
    CHAN_MAX = 4

class _StreamCloser:
    def __init__(self, stream):
        self._stream = stream
    def __enter__(self):
        return self._stream
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stream.close()

def extcap_config(interface, option, extcap_version):
    """List Configuration for the given interface"""
    args = []
    
    # Combined legacy selector logic with new requirements; using integer for direct user input.
    args.append((Config.CHANNEL.value, '--channel', 'Channel', 'IEEE 802.15.4 channel', 'integer', '{range=1,26}{default=11}'))
    
    # Added Sub-GHz channel range constraints.
    args.append((Config.CHAN_MIN.value, '--channel-min', 'Min Channel', 'Minimum Sub-GHz Channel', 'integer', '{default=1}'))
    args.append((Config.CHAN_MAX.value, '--channel-max', 'Max Channel', 'Maximum Sub-GHz Channel', 'integer', '{default=10}'))

    # Restored legacy Wireshark version check and TAP default syntax {default=yes}.
    match = re.match(r'^(\d+)(\.\d+)*$', extcap_version)
    if match and int(match.group(1)) >= 3:
        args.append((Config.TAP.value, '--tap',
                     'IEEE 802.15.4 TAP (only for Wireshark3.0 and later)',
                     'IEEE 802.15.4 TAP', 'boolflag', '{default=yes}'))

    for arg in args:
        print('arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s' % arg)


def extcap_dlts(interface):
    """List DLTs for the given interface"""
    # Restored legacy order: 195 must come first to prevent Bad FCS due to Wireshark dissection offset.
    print('dlt {number=195}{name=IEEE802_15_4_WITHFCS}{display=IEEE 802.15.4 with FCS}')
    print('dlt {number=283}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}')

def serialopen(interface, log_file):
    """Open serial to identify OpenThread sniffer"""
    # Restored legacy stdout redirection to prevent logs from polluting the Wireshark pipe.
    sys.stdout = log_file
    sys.stderr = log_file
    interface_name = str(interface).split()[0]
    baudrate = None

    for speed in COMMON_BAUDRATE:
        try:
            with _StreamCloser(StreamOpen('u', interface_name, False, baudrate=speed)) as stream, \
                    WpanApi(stream, nodeid=DEFAULT_NODEID, timeout=0.1) as wpan_api:
                result = wpan_api.prop_get_value(SPINEL.PROP_CAPS)
                if result is not None:
                    baudrate = speed
                    break
        except:
            continue

    if baudrate is not None:
        if sys.platform == 'win32':
            print('interface {value=%s:%s}{display=OpenThread Sniffer %s}' %
                  (interface_name, baudrate, interface_name),
                  file=sys.__stdout__, flush=True)
        else:
            print('interface {value=%s:%s}{display=OpenThread Sniffer}' %
                  (interface_name, baudrate),
                  file=sys.__stdout__, flush=True)

def extcap_interfaces():
    """List available interfaces to capture from"""
    log_file = open(os.path.join(tempfile.gettempdir(), 'extcap_ot_interfaces.log'), 'w')
    print('extcap {version=1.0.0}{display=OpenThread Sniffer}{help=https://github.com/RafaelMicro/pyspinel}')

    threads = []
    for interface in comports():
        th = threading.Thread(target=serialopen, args=(interface, log_file))
        threads.append(th)
        th.start()
    for th in threads:
        th.join()

def extcap_capture(interface, fifo, control_in, control_out, channel, tap, channel_min, channel_max):
    """Start the sniffer to capture packets"""
    # Added channel input validation.
    if channel is None or str(channel).strip() == '' or str(channel).lower() == 'none':
        sys.exit("\n [ERROR] Channel cannot be empty.")
    c_val = int(channel)
    c_min = int(channel_min) if channel_min else 1
    c_max = int(channel_max) if channel_max else 10
    if c_val < c_min or c_val > c_max:
        sys.exit(f"\n [ERROR] Channel {c_val} is out of range! (Valid range: {c_min} to {c_max})")

    interface_port = str(interface).split(':')[0]
    interface_baudrate = str(interface).split(':')[1] if ':' in str(interface) else "2000000"

    # Initialize Hardware.
    with _StreamCloser(StreamOpen('u', interface_port, False, baudrate=int(interface_baudrate))) as stream, \
            WpanApi(stream, nodeid=DEFAULT_NODEID) as wpan_api:
        wpan_api.prop_set_value(SPINEL.PROP_PHY_ENABLED, 1)

    extcap_dir = os.path.dirname(os.path.realpath(__file__))
    if sys.platform == 'win32':
        sniffer_py = os.path.join(extcap_dir, 'sniffer.py')
        if not os.path.exists(sniffer_py):
            sniffer_py = os.path.join(os.path.dirname(sys.executable), 'Scripts', 'sniffer.py')
        cmd = ['python', sniffer_py]
    else:
        cmd = ['sniffer.py']

    # Restored legacy startup argument order.
    cmd += [
        '-c', str(c_val), '-u', interface_port, '--crc', '--rssi', '-b',
        interface_baudrate, '-o', str(fifo), '--is-fifo', '--use-host-timestamp'
    ]
    if tap:
        cmd.append('--tap')

    subprocess.Popen(cmd).wait()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenThread Sniffer extcap plugin')

    # Extcap Arguments (Retained legacy configuration).
    parser.add_argument('--extcap-interfaces', action='store_true')
    parser.add_argument('--extcap-interface')
    parser.add_argument('--extcap-dlts', action='store_true')
    parser.add_argument('--extcap-config', action='store_true')
    parser.add_argument('--extcap-reload-option')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--fifo')
    parser.add_argument('--extcap-capture-filter')
    parser.add_argument('--extcap-control-in')
    parser.add_argument('--extcap-control-out')
    parser.add_argument('--extcap-version', help='Wireshark Version')

    # Interface Arguments.
    parser.add_argument('--channel')
    parser.add_argument('--channel-min')
    parser.add_argument('--channel-max')
    parser.add_argument('--tap', action='store_true')

    try:
        args, unknown = parser.parse_known_args()
    except argparse.ArgumentError as e:
        parser.exit('ERROR_ARG: %s' % str(e))

    # Restored legacy version caching mechanism to ensure TAP option displays correctly.
    extcap_version = ''
    version_path = os.path.join(tempfile.gettempdir(), 'extcap_ot_version')
    if args.extcap_version:
        extcap_version = args.extcap_version
        with open(version_path, mode='w') as f:
            f.write(extcap_version)
    else:
        try:
            with open(version_path, mode='r') as f:
                extcap_version = f.read()
        except FileNotFoundError:
            pass

    if args.extcap_interfaces:
        extcap_interfaces()
        sys.exit(0)

    if args.extcap_config:
        extcap_config(args.extcap_interface, '', extcap_version)
    elif args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
    elif args.capture:
        if args.fifo is None:
            parser.exit('The fifo must be provided to capture')
        try:
            extcap_capture(args.extcap_interface, args.fifo,
                           args.extcap_control_in, args.extcap_control_out,
                           args.channel, args.tap, args.channel_min, args.channel_max)
        except Exception as e:
            logging.exception(e)
            parser.exit('ERROR_INTERNAL')
