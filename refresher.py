import logging
import re
import time
import os
from pathlib import Path
from logging import Logger
import subprocess
from datetime import datetime
from configuration import Config, XmlParser
from scanner import scan_networks
from sql_connection import SqlConnection

log = logging.getLogger('refresher')
# log_file = os.path.join(Config.log_files_path, f'{__name__}.log')
# Config.config_logger(file=log_file)


def update_host_status(xml_res_file: Path | str) -> set[str]:
    rt = XmlParser(xml_res_file)
    count = 0
    ip_set = set()
    for host in rt.root.findall('host'):
        count += 1
        for host_addr in host.findall('address'):
            if host_addr.attrib['addrtype'] == 'ipv4':
                ip = host_addr.attrib['addr']
                break
        else:
            log.error(f'No ipv4 address found in the host {host}')
            continue
        state = host.find('status').attrib['state']
        if state == 'up':
            ip_set.add(ip)
    log.info(f'Found {count} alive hosts')
    return ip_set


def search_for_dead(one_cycle: bool = False) -> None:
    xml_res_file = Config.tmp_folder_path / 'nmap_search_for_dead.xml'
    temp_hosts_nmap = Config.tmp_folder_path / 'temp_hosts_nmap.txt'

    sql = SqlConnection()
    search_for_dead_timer = time.time()

    while True:
        hosts_ip_set = set()
        alive_ip_set = set()
        try:
            sql_tuples_up = sql.cursor.execute('SELECT ipv4 FROM hosts WHERE status="up"').fetchall()
            sql_tuples_down = sql.cursor.execute('SELECT ipv4 FROM hosts WHERE status="down"').fetchall()
            sql_tuples = sql_tuples_up + sql_tuples_down
            all_ips = len(sql_tuples)
            log.info(f'Found {all_ips} hosts')
            for i in range(0, all_ips, Config.search_for_dead_burst):
                # At first Try to scan manually newly added hosts
                not_scanned = sql.cursor.execute('SELECT ipv4 FROM hosts WHERE scanned=0').fetchall()
                for ipv4, in not_scanned:
                    scan_networks(sql, full_net_pattern=ipv4)
                with open(temp_hosts_nmap, 'w') as fh:
                    for ipv4, in sql_tuples[i:i + Config.search_for_dead_burst]:
                        fh.write(f'{ipv4} ')
                        hosts_ip_set.add(ipv4)
                log.info(f'Process [{i}:{i + 256}] hosts in the "hosts" table')
                cmd_str = (f'nmap.exe -sn -n -PE -Pn --max-rtt-timeout 200ms --disable-arp-ping --host-timeout'
                           f' 30s -oX {os.path.normcase(xml_res_file)} -iL {os.path.normcase(temp_hosts_nmap)}')
                log.debug(cmd_str)
                cmd_res = subprocess.run(
                    cmd_str,
                    timeout=200,
                    text=True,
                    capture_output=True,
                )
                log.debug(re.sub(r'[\n\r]+', r'\\n ', cmd_res.stdout))
                if cmd_res.returncode:
                    log.info(cmd_res.stderr)
                    log.error(f'ERROR! Failed to get hosts status')
                else:
                    log.info(f'The scanning hosts states passed successfully')
                alive_ip_set |= update_host_status(xml_res_file)
                time.sleep(Config.search_for_dead_period)

            dead_ip_set = hosts_ip_set - alive_ip_set
            log.debug(f'dead ips:\n{dead_ip_set}')
            log.info(f'Found {len(dead_ip_set)} dead hosts of {all_ips}')
            current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
            for ipv4 in hosts_ip_set:
                status = 'up'
                if ipv4 in dead_ip_set: status = 'down'
                update_str = f"updated='{current_date}', status='{status}'"
                sql_cmd = f"UPDATE hosts SET {update_str} WHERE ipv4='{ipv4}'"
                if status == 'down' and (ipv4,) in sql_tuples_up:
                    update_str += f", down_at='{current_date}'"
                sql.cursor.execute(sql_cmd)
                sql.conn.commit()
                time.sleep(0.1)
                if status == 'down':
                    #
                    # TODO -  check how long the host is in down state and delete
                    #
                    del_command = f"DELETE FROM hosts WHERE ipv4='{ipv4}'"
                    sql_cmd = (f"SELECT name,domain,keep,type,owner,sub_owner "
                               f"FROM hosts WHERE ipv4='{ipv4}'")
                    name, domain, keep, type, owner, sub_owner, *_ = sql.cursor.execute(sql_cmd).fetchall()[0]
                    if not [x for x in (keep, type, owner, sub_owner) if x]:
                        log.info(f'Delete dead host ({ipv4})- there is no owner or other identification')
                        sql.cursor.execute(del_command)
                        sql.conn.commit()
                    elif name:
                        h_list = sql.cursor.execute(
                            f"SELECT ipv4 FROM hosts WHERE name='{name}' AND domain='{domain}' AND type<>'AUDC'"
                        ).fetchall()
                        if len(h_list) > 1:
                            log.debug(h_list)
                            log.info(f'Found several ({len(h_list)}) hosts with the same name "{name}" - ',
                                     f'probably the IP {ipv4} changed (dhcp)')
                            log.info(f'Delete dead host {ipv4}')
                            sql.cursor.execute(del_command)
                            sql.conn.commit()
                sql.conn.commit()
        except Exception as err:
            log.critical('An exception happened during refresh cycle!!!', exc_info=err)
        if one_cycle: break


if __name__ == '__main__':
    search_for_dead(one_cycle=True)
