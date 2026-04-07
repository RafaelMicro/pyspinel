#!/usr/bin/env python3
"""
Rafael Micro OpenThread Sniffer Extcap Tool
Usage: Copy this file to Wireshark's extcap directory.
"""
import os
import sys
import tempfile
import argparse
import subprocess
import threading
import logging
from spinel.stream import StreamOpen
from spinel.const import SPINEL
from spinel.codec import WpanApi
from serial.tools.list_ports import comports
from enum import Enum

# Default Node ID for OpenThread NCP simulation
DEFAULT_NODEID = 34
# High-speed baudrates for Rafael Micro hardware
COMMON_BAUDRATE = [2000000, 115200, 9600]

class Config(Enum):
    """Mapping for Wireshark configuration UI elements"""
    CHANNEL = 0
    BAUDRATE = 1
    TAP = 2
    CHAN_MIN = 3
    CHAN_MAX = 4

class _StreamCloser:
    """Resource manager to ensure serial ports are released after probing"""
    def __init__(self, stream):
        self._stream = stream
    def __enter__(self):
        return self._stream
    def __exit__(self, exc_type, exc_val, exc_tb):
        self._stream.close()

def extcap_config(interface, option, version):
    """
    Generates the Wireshark configuration dialog.
    Parses the detected baudrate from the interface string for dynamic defaults.
    """
    try:
        # interface format: "COMx:detected_baud"
        detected_baud = str(interface).split(':')[1]
    except (IndexError, AttributeError):
        # Default fallback to 2Mbps if parsing fails
        detected_baud = "2000000"

    args = []
    # 1. Main Channel Input
    args.append((Config.CHANNEL.value, '--channel', 'Channel', 'Select capture channel', 'integer', '{range=1,26}{default=11}'))
    # 2. Baudrate Override Selector
    args.append((Config.BAUDRATE.value, '--baudrate', 'Baudrate', 'Force UART Baudrate', 'selector', ''))
    # 3. Frequency Band Limits (Sub-GHz)
    args.append((Config.CHAN_MIN.value, '--channel-min', 'Min Channel', 'Minimum Sub-GHz Channel', 'integer', '{default=1}'))
    args.append((Config.CHAN_MAX.value, '--channel-max', 'Max Channel', 'Maximum Sub-GHz Channel', 'integer', '{default=10}'))

    for arg in args:
        print('arg {number=%d}{call=%s}{display=%s}{tooltip=%s}{type=%s}%s' % arg)

    # Output Baudrate options, marking the detected one as default
    baudrate_list = ["115200", "1000000", "2000000"]
    for b in baudrate_list:
        is_default = "{default=true}" if b == detected_baud else ""
        print('value {arg=%d}{value=%s}{display=%s}%s' % (Config.BAUDRATE.value, b, b, is_default))

def extcap_dlts(interface):
    """Informs Wireshark about the data link layer types supported"""
    print('dlt {number=195}{name=IEEE802_15_4_WITHFCS}{display=IEEE 802.15.4 with FCS}')
    print('dlt {number=283}{name=IEEE802_15_4_TAP}{display=IEEE 802.15.4 TAP}')

def serialopen(interface, log_file):
    """Probes a COM port to check for valid Spinel NCP hardware"""
    interface_name = str(interface).split()[0]
    baudrate = None
    for speed in COMMON_BAUDRATE:
        try:
            with _StreamCloser(StreamOpen('u', interface_name, False, baudrate=speed)) as stream, \
                    WpanApi(stream, nodeid=DEFAULT_NODEID, timeout=0.1) as wpan_api:
                # Validate hardware by requesting Spinel Capabilities
                if wpan_api.prop_get_value(SPINEL.PROP_CAPS) is not None:
                    baudrate = speed
                    break
        except:
            continue
    
    if baudrate is not None:
        # Reports the interface to Wireshark if hardware is found
        print('interface {value=%s:%s}{display=OpenThread Sniffer %s}' % (interface_name, baudrate, interface_name), file=sys.__stdout__, flush=True)

def extcap_interfaces():
    """System-wide scan for all available sniffer hardware"""
    print('extcap {version=1.0.0}{display=OpenThread Sniffer}{help=https://github.com/RafaelMicro/pyspinel}')
    threads = [threading.Thread(target=serialopen, args=(interface, None)) for interface in comports()]
    for th in threads: th.start()
    for th in threads: th.join()

def extcap_capture(interface, fifo, channel, tap, baudrate, channel_min, channel_max):
    """Performs pre-capture validation and starts the sniffer core"""
    # 1. Ensure channel is provided
    if channel is None or str(channel).lower() == 'none' or str(channel).strip() == '':
        sys.exit("\n [ERROR] Channel cannot be empty. Please select a valid channel.")

    # 2. Enforce boundary checks
    c_val = int(channel)
    c_min = int(channel_min) if channel_min else 1
    c_max = int(channel_max) if channel_max else 10

    if c_val < c_min or c_val > c_max:
        sys.exit(f"\n [ERROR] Channel {c_val} is out of range! (Valid range: {c_min} to {c_max})")

    # Determine connection parameters
    interface_port = str(interface).split(':')[0]
    detected_baud = str(interface).split(':')[1] if ':' in str(interface) else "2000000"
    final_baudrate = baudrate if baudrate else detected_baud

    extcap_dir = os.path.dirname(os.path.realpath(__file__))
    
    if sys.platform == 'win32':
        sniffer_py = os.path.join(extcap_dir, 'sniffer.py')
        if not os.path.exists(sniffer_py):
            sniffer_py = os.path.join(os.path.dirname(sys.executable), 'Scripts', 'sniffer.py')
        cmd = ['python', sniffer_py]
    else:
        cmd = ['sniffer.py']

    # Execute sniffer.py with parsed arguments
    cmd += [
        '-c', str(c_val), 
        '-u', interface_port, 
        '-b', str(final_baudrate), 
        '--crc', '--rssi', 
        '-o', str(fifo), 
        '--is-fifo', 
        '--use-host-timestamp'
    ]
    if tap:
        cmd.append('--tap')

    subprocess.Popen(cmd).wait()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='OpenThread Sniffer extcap for Rafael Micro')
    
    # Wireshark Standard Arguments
    parser.add_argument('--extcap-interfaces', action='store_true')
    parser.add_argument('--extcap-interface')
    parser.add_argument('--extcap-dlts', action='store_true')
    parser.add_argument('--extcap-config', action='store_true')
    parser.add_argument('--capture', action='store_true')
    parser.add_argument('--fifo')
    
    # Configuration Arguments
    parser.add_argument('--channel')
    parser.add_argument('--baudrate')
    parser.add_argument('--channel-min')
    parser.add_argument('--channel-max')
    parser.add_argument('--tap', action='store_true')
    
    # Metadata Arguments
    parser.add_argument('--extcap-version')
    parser.add_argument('--extcap-control-in')
    parser.add_argument('--extcap-control-out')
    parser.add_argument('--extcap-reload-option')
    parser.add_argument('--extcap-capture-filter')

    args, unknown = parser.parse_known_args()

    if args.extcap_interfaces:
        extcap_interfaces()
    elif args.extcap_config:
        extcap_config(args.extcap_interface, '', '')
    elif args.extcap_dlts:
        extcap_dlts(args.extcap_interface)
    elif args.capture:
        if args.fifo is None:
            sys.exit('Fatal: FIFO pipe must be specified for capture.')
        try:
            extcap_capture(
                args.extcap_interface, 
                args.fifo, 
                args.channel, 
                args.tap, 
                args.baudrate,
                args.channel_min,
                args.channel_max
            )
        except Exception as e:
            logging.exception(e)
            sys.exit('ERROR_INTERNAL')
