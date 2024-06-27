from pathlib import Path
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import sys
import os
from enum import Enum
import traceback
import xml.etree.ElementTree as eT

ALLOW_SCAN = True


class ScanMode(Enum):
    FULL = 0
    SELECTED = 1


scan_mode = ScanMode.SELECTED

log_files_path = Path(__file__).parent / 'logs'
log_files_path.mkdir(exist_ok=True)
tmp_folder_path = Path(__file__).parent / 'tmp'
tmp_folder_path.mkdir(exist_ok=True)

log_file = os.path.join(log_files_path, 'netscan_main_log.txt')

selected_b_networks = (
    '10.8',
    '10.17',
    '10.15',
    '10.3',
    '10.4',
    '10.7',
    '10.31',
    '10.33',
    '172.17',
)
alive_net_refresh_period = 21600  # in seconds
search_for_dead_period = 4
search_for_dead_burst = 5
sleep_between_c_networks_scan = 10
filter_os_for_AUDC_scan = "os<>'Windows' AND os<>'JUNOS' AND os<>'iLO' AND os<>'ESXi' AND \
os<>'FreeBSD' AND os<>'OpenBSD' AND os<>'Data ONTAP' and os<>'IOS' AND os<>'AOS' AND os<>'FreeNAS' \
AND os<>'Android' AND os<>'DESQview/X' AND os<>'Solaris' AND os<>'CyanogenMod'"

networks_A_list = ['10', '172']
exclude_networks = ['10.44.0.0/16', '10.128.0.0/16', '10.255.0.0/16', '10.250.0.0/16',
                    '10.91.0.0/16', '10.191.0.0/16', '10.66.0.0/16', '10.59.0.0/16',
                    '10.22.0.0/16',
                    ]
exclude_networks_obj_list = [ipaddress.ip_network(net) for net in exclude_networks]
exclude_file = tmp_folder_path / f'exclude_networks.txt'
with open(exclude_file, 'w') as fh:
    fh.write('\n'.join(exclude_networks))

check_ports_dict = {'T:22': 'ssh', 'T:80': 'http', 'T:443': 'https', 'T:3389': 'rdp'}
sql_fields = {
    'ipv4': 'char(17) primary key',
    'name': 'char(32)',
    'os': 'char(32)',
    'status': 'char(6)',
    'owner': 'char(20)',
    'type': 'char(25)',
    'productType': 'vchar(50)',
    'upTime': 'int',
    'sub_owner': 'char(20)',
    'version': 'char(25)',
    'HA': 'char(3)',
    'ssh': 'char(2)',
    'http': 'char(2)',
    'https': 'char(2)',
    'rdp': 'char(2)',
    'down_at': 'date',
    'mac': 'char(12)',
    'macvendor': 'vchar(25)',
    'domain': 'vchar(60)',
    'username': 'char(32)',
    'password': 'char(32)',
    'serialNumber': 'char(32)',
    'keep': 'char(16)',
    'location': 'char(128)',
    'description': 'char(512)',
    'updated': 'date',
    'web_server': 'char(32)',
    'audc': 'int',
    'scanned': 'int',
    }
fields_defaults = {}
for prot in check_ports_dict:
    if check_ports_dict[prot] in sql_fields.keys():
        fields_defaults[check_ports_dict[prot]] = 'x'

for key in sql_fields:
    if key not in fields_defaults:
        fields_defaults[key] = ''

hosts_names_str = ','.join([*sql_fields])


class XmlParser:
    def __init__(self, xml_res_file):
        tree = eT.parse(xml_res_file)
        self.root = tree.getroot()


def config_logger(file=log_file, debug='yes', separate_stderr='no', logger_name=''):
    print(f'Initializing Logger, log file "{file}", logger name "{logger_name}"')

    # configure file log handler
    log_file_handler = RotatingFileHandler(file, maxBytes=100_000_000, backupCount=5)
    log_file_handler.setFormatter(logging.Formatter('%(asctime)s %(levelname)-7s: %(name)-12s: %(message)s'))
    log_file_handler.setLevel(logging.DEBUG)
    handlers_list = [log_file_handler, ]

    # configure console logger
    formatter = logging.Formatter('%(levelname)-7s: %(name)-12s: %(message)s')
    if debug == 'yes':
        low_level = logging.DEBUG
    else:
        low_level = logging.INFO

    streams_list = [[sys.stdout, low_level], ]
    if separate_stderr != 'no':
        streams_list = [[sys.stdout, low_level], [sys.stderr, logging.WARNING]]
    for stream, level in streams_list:
        stream_h = logging.StreamHandler(stream)
        handlers_list.append(stream_h)
        stream_h.setLevel(level)
        stream_h.setFormatter(formatter)
        if level <= logging.INFO and separate_stderr != 'no':
            stream_h.addFilter(lambda msg: msg.levelno <= logging.INFO)

    logging.basicConfig(handlers=handlers_list, level=low_level, )
    log = logging.getLogger(logger_name)
    log.info('-- Start logger --')
    return log


def get_b_network_for_scan(b_range=256):
    if scan_mode == ScanMode.SELECTED:
        return selected_b_networks
    elif scan_mode == ScanMode.FULL:
        return range(b_range)
    else:
        raise Exception(f'Bad ScanMode {scan_mode}')

