"""
default global configuration for the application,
the configuration is overridden by appsettings.json file settings
"""
import sys
from pathlib import Path
import ipaddress
import logging
from logging.handlers import RotatingFileHandler
import xml.etree.ElementTree as eT
from typing import Optional

sys.path.insert(0, Path(__file__).parent)


class Config:
    ALLOW_SCAN: bool = True
    ALLOW_AUDC_PLUGIN: bool = False
    START_WEB_APP: bool = True
    web_app_port: int = 5000
    web_app_name: str = 'flask_app'
    web_server_app_path: str  = 'web_app/waitress_server.py'
    scanner_app_name: str = 'netscan_app'
    root_path: Path = Path(__file__).parent
    log_files_path: Path = root_path / 'logs'
    log_files_path.mkdir(exist_ok=True)
    tmp_folder_path: Path = root_path / 'tmp'
    tmp_folder_path.mkdir(exist_ok=True)
    log_file: Path = log_files_path / 'netscan.log'
    search_for_dead_period: int = 4
    search_for_dead_burst: int = 5
    sleep_between_c_networks_scan: int = 10
    filter_os_for_AUDC_scan: str = "os<>'Windows' AND os<>'JUNOS' AND os<>'iLO' AND os<>'ESXi' AND \
    os<>'FreeBSD' AND os<>'OpenBSD' AND os<>'Data ONTAP' and os<>'IOS' AND os<>'AOS' AND os<>'FreeNAS' \
    AND os<>'Android' AND os<>'DESQview/X' AND os<>'Solaris' AND os<>'CyanogenMod'"

    selected_networks: tuple[str] | list[str] = ('10.8.0.0/16', '10.3.0.0/16')
    exclude_networks: tuple[str] | list[str] = ()
    exclude_networks_obj_list: list[ipaddress] = [ipaddress.ip_network(net) for net in exclude_networks]
    exclude_file: Path = tmp_folder_path / f'exclude_networks.txt'
    with open(exclude_file, 'w') as fh:
        fh.write('\n'.join(exclude_networks))

    check_ports_dict: dict[str, str] = {'T:22': 'ssh', 'T:80': 'http', 'T:443': 'https', 'T:3389': 'rdp'}
    sql_fields: dict[str, str] = {
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
    fields_defaults: dict = {}
    for prot in check_ports_dict:
        if check_ports_dict[prot] in sql_fields.keys():
            fields_defaults[check_ports_dict[prot]] = 'x'
    for key in sql_fields:
        if key not in fields_defaults:
            fields_defaults[key] = ''
    hosts_names_str: str = ','.join([*sql_fields])

    @staticmethod
    def config_logger(file: str | Path = '', filter_logger: Optional[logging.Logger] = None, debug='yes') -> None:
        format_str: str = '%(levelname)-7s: %(name)-12s: %(message)s'
        low_level = logging.DEBUG if debug == 'yes' else logging.INFO
        logging.basicConfig(level=low_level, format=format_str)
        if file:
            # configure file log handler
            formatter: logging.Formatter = logging.Formatter('%(asctime)s ' + format_str)
            log_file_handler = RotatingFileHandler(file, maxBytes=100_000_000, backupCount=5)
            log_file_handler.setFormatter(formatter)
            log_file_handler.setLevel(logging.DEBUG)
            root_logger: logging.Logger = logging.getLogger()
            for handler in root_logger.handlers:
                if isinstance(handler, logging.FileHandler):
                    root_logger.debug(f'Root logger already has a file handler: {handler.baseFilename}')
                    if handler.baseFilename == log_file_handler.baseFilename:
                        root_logger.warning(f'Root logger already has a file handler with the same file: {file}'
                                            ' (no need to add another one)')
                        break
            else:
                if filter_logger:
                    log_file_handler.addFilter(logging.Filter(name=filter_logger.name))
                root_logger.addHandler(log_file_handler)
        elif filter_logger:
            raise Exception('filter_logger is not None, but file is empty')


class XmlParser:
    def __init__(self, xml_res_file):
        tree = eT.parse(xml_res_file)
        self.root = tree.getroot()


if (Path(__file__).parent / 'appsettings.json').exists():
    import json
    with open(Path(__file__).parent / 'appsettings.json') as fh:
        app_settings = json.load(fh)
    for key in app_settings:
        if key not in dir(Config):
            raise Exception(f'Bad key in appsettings.json: {key}')
        setattr(Config, key, app_settings[key])
