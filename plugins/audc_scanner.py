import re
from pathlib import Path
import logging
import aiohttp
import asyncio
import requests
import time
import ipaddress
from datetime import datetime

from bs4 import BeautifulSoup
from requests.auth import HTTPDigestAuth

from sql_connection import SqlConnection, remove_bad_symbols
from configuration import Config

log = logging.getLogger('audc_sc')
# Log messages in separate log file
# log_file = Path(Config.log_files_path) / f'{__name__}.log'
# Config.config_logger(file=log_file, filter_logger=log)

INTER_SCAN_DELAY = 1200

rest_2_sql_map = dict(
    productType='productType',
    systemUpTime='upTime',
    versionID='version',
    highAvailability='HA',
    macAddress='mac',
    serialNumber='serialNumber',
    )
# add old HW web parameters
rest_2_sql_map.update({
    'Serial Number': 'serialNumber',
    'MAC Address': 'mac',
    'Device Up Time': 'upTime',
    'Version ID': 'version',
    'Board Type': 'productType',
})
"""
'Device Information', 'General',
' MAC Address ', '00908f584979',
' Serial Number ', '5785977',
' Board Type ', '56',
' Device Up Time ', '0d 5h 41m 12s 90th ',
' Device Administrative State ', 'Unlocked',
' Device Operational State ', 'Enabled',
' Flash Size [bytes] ', '8388608',
' RAM Size [bytes] ', '33554432',
' CPU Speed [MHz] ', '40',
'Versions', ' Version ID ', '5.00.054.001', 
' DSP Type ', '0',
' DSP Software Version ', '20922',
' DSP Software Name ', '204IM ', 
' Flash Version ', '199', 'Loaded Files', ' ',
'Call Progress Tones File Name ', 'test_fxo_progress.dat',
'Pre Recorded Tones File Name ', 'plz_wait.dat',
'Loaded Coder Table ', 'Default CODERTABLE']
"""
max_simult_scan: int = 512
db_audc_filter: str = (f"SELECT ipv4,username,password FROM hosts WHERE "
                       f"(status='up' AND http='ok' and {Config.filter_os_for_AUDC_scan}"
                       f" and type='' or type='AUDC')")


async def audc_scanner(host):
    ip, username, password, *_ = host
    if username == '': username = 'Admin'
    if password == '': password = 'Admin'
    try:
        async with aiohttp.ClientSession(auth=aiohttp.BasicAuth(username, password)) as session:
            async with session.get(f'http://{ip}/api/v1/status') as r:
                await r.read()
                result_dic = dict(ip=ip, headers=r.headers, status=r.status)
                if r.status == 200:
                    result_dic['result'] = 'OK!'
                    result_dic['value'] = await r.json()
                else:
                    result_dic['result'] = 'FAILED!'
                    result_dic['value'] = r.text
    except Exception as err:
        result_dic = dict(result='EXCEPTION!', status=0, ip=ip, headers={}, value=err)
    return result_dic


async def set_concurrent_clients(hosts):
    return await asyncio.gather(*(audc_scanner(host) for host in hosts))


def run_audc_scanner(one_loop=False):
    sql = SqlConnection()
    while True:
        try:
            # Get all alive hosts with http
            audc_hosts = sql.cursor.execute(db_audc_filter).fetchall()
            # audc_hosts = (('10.8.41.182', 'Admin', 'Admin'), ('10.8.94.152', '', ''),)
            hosts_to_scan = len(audc_hosts)
            found_audc_hosts = 0
            start_scan_timestamp = time.time()
            log.debug(f'Found {hosts_to_scan} potential AUDC hosts')
            audc_c_networks = {}
            for index in range(0, hosts_to_scan, max_simult_scan):
                temp_hosts_list = audc_hosts[index:index + max_simult_scan]
                log.info(f"Start http scan of {index} - {index+max_simult_scan} range")
                start_time_stamp = time.time()
                results = asyncio.run(set_concurrent_clients(temp_hosts_list))
                log.debug(f'The scan took {time.time() - start_time_stamp} seconds')
                for res in results:
                    if process_rest_result(sql, res):
                        found_audc_hosts += 1
                        ip_c_net = ipaddress.ip_network(res['ip'] + '/24', False).network_address.__str__()
                        audc_c_networks[ip_c_net] = audc_c_networks.get(ip_c_net, 0) + 1

            for audc_c_net, count in audc_c_networks.items():
                update_str = f"UPDATE alive_networks SET audc={count} WHERE network='{audc_c_net}/24'"
                if not sql.cursor.execute(update_str).rowcount:
                    log.error(f'{update_str} \n Failed to update alive_networks SQL table')
                sql.conn.commit()

            log.debug(f'The rest scan took {time.time() - start_scan_timestamp} sec, found {found_audc_hosts} audc')
        except Exception as ex:
            log.exception("ERROR! Exception in while loop", exc_info=True)
        finally:
            if one_loop: break
            time.sleep(INTER_SCAN_DELAY)


def run_audc_scanner_old_hw(one_loop: bool = False, ip: str = '', user: str = '', password: str = ''):
    sql = SqlConnection()
    while True:
        # Get all alive AUDc hosts with http and os='embedded'
        if ip:
            audc_hosts = [(ip, user, password)]
        else:
            audc_hosts = sql.cursor.execute(
                (f"SELECT ipv4,username,password FROM hosts WHERE "
                 f"(status='up' AND http='ok' and os='embedded' and type='AUDC')")
            ).fetchall()
        hosts_to_scan = len(audc_hosts)
        found_audc_hosts = 0
        start_scan_timestamp = time.time()
        log.debug(f'Found {hosts_to_scan} potential old HW AUDC hosts')

        for host in audc_hosts:
            try:
                ip, username, password, *_ = host
                if username == '': username = 'Admin'
                if password == '': password = 'Admin'
                result_dic = dict(ip=ip, result='FAILED!', value={}, headers={})
                res = requests.get(f'http://{ip}/SoftwareVersion', auth=HTTPDigestAuth(username, password))
                result_dic['status'] = res.status_code
                result_dic['headers'] = res.headers
                if res.status_code == 200:
                    found_audc_hosts += 1
                    result_dic['result'] = 'OK!'
                    sp = BeautifulSoup(res.text, 'html.parser')
                    res_txt = re.sub(r'\n+', '\n', re.sub(r'\xa0+', ' ', sp.text))
                    res_list = [el.strip() for el in re.sub(r' *: *', '', res_txt).split('\n')]
                    log.debug(f'{ip=} - {res_list}')
                    for key in rest_2_sql_map:
                        if key in res_list:
                            result_dic['value'][key] = res_list[res_list.index(key) + 1]
                    process_rest_result(sql, result_dic)
                else:
                    result_dic['value'] = res.text
            except:
                log.exception("ERROR! Exception in old HW loop", exc_info=True)
            if one_loop: break
            time.sleep(1)
        if one_loop: break
        time.sleep(600)
        log.debug(f'The rest scan took {time.time() - start_scan_timestamp} sec,'
                  f' discovered {found_audc_hosts} old HW audc (out of {hosts_to_scan=})')


def process_rest_result(sql, res) -> bool:
    sql_update_list = []
    server = res["headers"].get("Server", "UNKNOWN")
    status = res.get('status', 0)
    if status == 404:
        if server.find('Allegro-Software-RomPager/3.10') == 0 or server.find('AudioCodes') != -1:
            log.info(f'{res["ip"]} - probably old AUDC device, the server "{server}"')
            sql_update_list.append("type='AUDC'")
        elif server.find('lighttpd/1.4.') == 0:
            log.info(f'{res["ip"]} - probably AUDC phone, the server "{server}"')
            sql_update_list.append("type='AC_PHONE'")
        else:
            log.info(f'{res["ip"]} - the REST path is not found server "{server}": NOT AUDC device')
            sql_update_list.append("type='NOT_AC'")
    if status in (401, 404, 200):
        pass
        sql_update_list.append(f"web_server='{server}'")
    if res['result'] == 'OK!':
        json_dict = res['value']
        for key in json_dict:
            if rest_2_sql_map.get(key):
                val = json_dict[key]
                if key != 'systemUpTime': val = remove_bad_symbols(json_dict[key])
                sql_update_list.append(f"{rest_2_sql_map.get(key)}='{val}'")
        if not sql_update_list:
            log.info(f'{res["ip"]} return OK on REST request but no device information found')
        sql_update_list.append("type='AUDC'")
    if not sql_update_list:
        log.info(f'{res["result"]} while gets status of {res["ip"]}, Error: "{res["value"]}" ')
    else:
        current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
        sql_update_list.append(f"updated='{current_date}'")
        update_str = f"UPDATE hosts SET {','.join(sql_update_list)} WHERE ipv4='{res['ip']}'"
        log.debug(update_str)
        updated = sql.cursor.execute(update_str).rowcount
        sql.conn.commit()
        if not updated:
            log.error(f'{update_str} \n Failed to update SQL table')
    if "type='AUDC'" in sql_update_list:
        return True
    return False



if __name__ == '__main__':
    run_audc_scanner(one_loop=True)
