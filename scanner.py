import logging
from typing import Optional
import subprocess
import os
import re
import ipaddress
import socket
from datetime import datetime
from configuration import Config, XmlParser

log = logging.getLogger('scanner')


def scan_networks(
        sql: object,
        subnet_a: Optional[int] = None,
        subnet_b: Optional[int] = None,
        subnet_c: Optional[int] = None,
        full_net_pattern: Optional[str] = None,
        xml_res_file: str = Config.tmp_folder_path / 'nmap_res.xml',
        only_public: bool = True,
        discovery_mode: str = 'PS',
        ) -> int:
    """ scan a subnet or a host for open ports for and update the hosts table
    :param sql:
    :param subnet_a:
    :param subnet_b:
    :param subnet_c:
    :param full_net_pattern:
    :param xml_res_file:
    :param only_public:
    :param discovery_mode: nmap discovery mode - PS, PE
    :return:
    """
    pn_param: str = ''
    hostname: str = ''
    found: int = 0
    if full_net_pattern:
        scan_pattern = full_net_pattern
    else:
        scan_pattern = f'{subnet_a}.{subnet_b}.{subnet_c}.0/24'
    try:
        ipaddress.ip_network(scan_pattern)
        if only_public and not ipaddress.ip_network(scan_pattern).is_private:
            log.info(f'The network {scan_pattern} is public - cannot run scan on public networks')
            return -1
        for f_net in Config.exclude_networks_obj_list:
            if ipaddress.ip_network(scan_pattern).subnet_of(f_net):
                log.info(f'The network {scan_pattern} is found as excluded from scan network')
                return -1
    except ValueError:
        log.info(f'The {scan_pattern=} is not a valid network - is it host? - try to resolve FQDN')
        try:
            log.info(f'{scan_pattern} = {socket.gethostbyname(scan_pattern)}')
            hostname = scan_pattern
        except:
            pass
        pn_param = '-Pn'
    log.info(f'start scanning the {scan_pattern}')
    cmd_str = f'nmap.exe -p {",".join([*Config.check_ports_dict])} -O --max-rtt-timeout 100ms --disable-arp-ping \
--host-timeout 30s -sT -{discovery_mode} {pn_param} -oX {os.path.normcase(xml_res_file)} --excludefile {Config.exclude_file} {scan_pattern}'

    log.debug(cmd_str)
    cmd_res = subprocess.run(
        cmd_str,
        timeout=240,
        text=True,
        capture_output=True,
    )
    log.info(cmd_res.stdout)
    if cmd_res.returncode:
        log.info(cmd_res.stderr)
        log.error(f'ERROR! Failed to enumerate {scan_pattern} subnet')
    else:
        log.info(f'The scanning "{scan_pattern}" subnet passed successfully')
        found = process_nmap_res(sql, xml_res_file, hostname=hostname)
        if found:
            sql.update_alive_networks_table(scan_pattern, found)
    return found


def process_nmap_res(sql, xml_res_file, hostname: str = ''):
    rt = XmlParser(xml_res_file)
    count = 0
    current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
    for host in rt.root.findall('host'):
        count += 1
        host_obj = dict()
        for host_addr in host.findall('address'):
            host_obj['ipv4'] = hostname if hostname else host_addr.attrib['addr']
            if host_addr.attrib['addrtype'] == 'mac' and host_addr.attrib.get('vendor', None):
                host_obj['macvendor'] = host_addr.attrib['vendor']
        prots_el = host.find('ports')
        if prots_el is not None:
            for port in prots_el:
                prot_prefix = ''
                if port.attrib['protocol'] == 'tcp': prot_prefix = 'T:'
                elif port.attrib['protocol'] == 'udp': prot_prefix = 'U:'
                else: log.warning(f"Unlisted protocol found: '{port.attrib['protocol']}'")
                check_prot_name = Config.check_ports_dict.get(prot_prefix + port.attrib['portid'], None)
                if check_prot_name and port.find('state').attrib['state'] == 'open':
                    host_obj[check_prot_name] = 'ok'
        else:
            log.debug(f"no ports listed for {host_obj['ipv4']}")
        hostname = host.find('hostnames').find('hostname')
        if hostname is not None:
            host_obj['name'] = hostname.attrib['name']
            re_res = re.search(r'^([^\.]+)\.(.+)$', hostname.attrib['name'])
            if re_res:
                host_obj['name'], host_obj['domain'] = re_res.groups('')
        try:
            host_obj['os'] = host.find('os').find('osmatch').find('osclass').attrib['osfamily']
        except:
            pass
        host_obj['status'] = 'up'
        host_obj['scanned'] = '1'
        log.info(host_obj)
        sql.update_hosts_table(host_obj, current_date, False)
        sql.conn.commit()
    log.info(f'Found {count} hosts in "{xml_res_file}"')
    return count
