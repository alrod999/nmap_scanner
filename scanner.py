from pathlib import Path
import subprocess
import os
import re
from datetime import datetime
import logging
import configuration as conf

log = logging.getLogger(__name__)


def scan_networks(
        sql,
        subnet_a=None,
        subnet_b=None,
        subnet_c=None,
        full_net_pattern=None,
        xml_res_file=conf.tmp_folder_path / 'nmap_res.xml',
        only_public=True,
        ):
    if full_net_pattern:
        scan_pattern = full_net_pattern
    else:
        scan_pattern = f'{subnet_a}.{subnet_b}.{subnet_c}.0/24'

    if only_public and not conf.ipaddress.ip_network(scan_pattern).is_private:
        log.info(f'The network {scan_pattern} is public - cannot run scan on public networks')
        return -1

    for f_net in conf.exclude_networks_obj_list:
        if conf.ipaddress.ip_network(scan_pattern).subnet_of(f_net):
            log.info(f'The network {scan_pattern} is found as excluded from scan network')
            return -1
    exclude_file = conf.tmp_folder_path / f'{Path(__file__).stem}.txt'
    with open(exclude_file, 'w') as fh:
        fh.write('\n'.join(conf.exclude_networks))

    log.info(f'start scanning the {scan_pattern}')
    cmd_str = f'nmap.exe -p {",".join([*conf.check_ports_dict])} -O --max-rtt-timeout 100ms --disable-arp-ping \
--host-timeout 30s -sT -PE -oX {os.path.normcase(xml_res_file)} --excludefile {exclude_file} {scan_pattern}'

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
        found = process_nmap_res(sql, xml_res_file)
        if found:
            sql.update_alive_networks_table(scan_pattern, found)
    return found


def process_nmap_res(sql, xml_res_file):
    rt = conf.XmlParser(xml_res_file)
    count = 0
    current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
    for host in rt.root.findall('host'):
        count += 1
        host_obj = dict()
        for host_addr in host.findall('address'):
            host_obj[host_addr.attrib['addrtype']] = host_addr.attrib['addr']
            if host_addr.attrib['addrtype'] == 'mac' and host_addr.attrib.get('vendor', None):
                host_obj['macvendor'] = host_addr.attrib['vendor']
        prots_el = host.find('ports')
        if prots_el is not None:
            for port in prots_el:
                prot_prefix = ''
                if port.attrib['protocol'] == 'tcp': prot_prefix = 'T:'
                elif port.attrib['protocol'] == 'udp': prot_prefix = 'U:'
                else: log.warning(f"Unlisted protocol found: '{port.attrib['protocol']}'")
                check_prot_name = conf.check_ports_dict.get(prot_prefix + port.attrib['portid'], None)
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
        log.info(host_obj)
        sql.update_hosts_table(host_obj, current_date, False)
    sql.conn.commit()
    log.info(f'Found {count} hosts in "{xml_res_file}"')
    return count
