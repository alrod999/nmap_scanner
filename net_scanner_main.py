import sys
import os
import logging
import subprocess
import time
import ipaddress
from datetime import datetime
from multiprocessing import Process
from configuration import Config
from sql_connection import SqlConnection
from refresher import search_for_dead
from scanner import scan_networks
from plugins.audc_scanner import run_audc_scanner

log = logging.getLogger('main')
Config.config_logger(Config.log_file)


def test_for_new_networks(sql_handler: SqlConnection) -> list[tuple]:
    return [el[0] for el in
            sql_handler.cursor.execute('SELECT network FROM b_networks WHERE updated is NULL').fetchall()]


def get_networks_for_scan(sql_handler: SqlConnection) -> list[str]:
    res: list[tuple]
    # Prioritize the networks that were not updated yet
    if res := test_for_new_networks(sql_handler):
        return res
    return [el[0] for el in sql_handler.cursor.execute('SELECT network FROM b_networks WHERE status != "invalid"').fetchall()]


def check_process_is_running(sql_handler: SqlConnection, name: str) -> bool:
    running_app = sql_handler.get_all_rows_in_table('applications', select='pid', sql_filter=f'application="{name}"')
    if not running_app:
        return False
    pid, *_ = running_app[0]
    res = subprocess.run(
        [f'tasklist.exe', '/FI', f'PID eq {pid}', '/FI', 'IMAGENAME eq python.exe', '/NH'],
        capture_output=True, text=True
    )
    log.debug(res.stdout + res.stderr)
    if str(pid) in res.stdout:
        log.info(f'The {name} process with {pid=} is already running, my_PID={os.getpid()=}')
        return True
    log.info(f'The {name} process with {pid=} is not running, {os.getpid()=}')
    return False


if __name__ == '__main__':
    sql = SqlConnection()
    if Config.START_WEB_APP and not check_process_is_running(sql, Config.web_app_name):
        command = ["./venv/Scripts/python.exe", Config.web_server_app_path]
        log.info(f'Start the {Config.web_app_name} application ({command})')
        # Start the command in a non-blocking way
        web_process: subprocess.Popen = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        sql.update_table(
            'applications', ('pid',),
            (web_process.pid,),
            f'application="{Config.web_app_name}"',
            update_date=True
        )
        time.sleep(3)
        if not check_process_is_running(sql, Config.web_app_name):
            log.error(f'The {Config.web_app_name} application failed to start!')
            stdout, stderr = web_process.communicate()
            log.error(f'{stdout=}\n{stderr=}')
            if ret_code := web_process.poll():
                log.error(f"Process {Config.web_app_name} finished with return code: {ret_code}")
            else:
                log.error(f"{Config.web_app_name} Process is still running? {os.getpid()=}")
            os._exit(1)
    if check_process_is_running(sql, Config.scanner_app_name):
        os._exit(1)
    log.info('== Start the main process of the scanner ==')
    sql.update_table(
        'applications', ('pid',),
        (os.getpid(),),
        f'application="{Config.scanner_app_name}"',
        update_date=True
    )
    log.info('Start the refresher (search_for_dead process)')
    p_refresher: Process = Process(target=search_for_dead,)
    p_refresher.daemon = True
    p_refresher.start()
    log.info('Start the AUDC plugin (run_audc_scanner process)')
    p_audc_scanner: Process = Process(target=run_audc_scanner,)
    p_audc_scanner.daemon = True
    p_audc_scanner.start()
    sql.update_table('b_networks', ('status',), ('idle',), 'status!="invalid"', update_date=False, )
    while True:
        try:
            if not Config.ALLOW_SCAN:
                # Only the refreshing is allowed
                time.sleep(1)
                continue
            b_net_hosts_num = {}
            found_all = 0
            networks_for_scan: list[str] = get_networks_for_scan(sql)
            if len(networks_for_scan) == 0:
                log.critical('There are no networks to scan!')
                exit(1)
            for subnet_ab_str in networks_for_scan:
                log.info(f'start scanning the "{subnet_ab_str}" network')
                subnet_ab = ipaddress.ip_network(subnet_ab_str)
                if not subnet_ab.is_private:
                    log.info(f'The network {subnet_ab} is not private - cannot run scan on public networks')
                    sql.update_table(
                        'b_networks',
                        ('status', ),
                        ('invalid',),
                        f"network='{subnet_ab_str}'",
                        update_date=True,
                    )
                    continue
                b_net_hosts_num[subnet_ab_str] = 0
                prefix_len: int = 24 if subnet_ab.prefixlen < 24 else subnet_ab.prefixlen
                sql.update_table(
                    'b_networks',
                    ('status', ),
                    ('scanning',),
                    f"network='{subnet_ab_str}'",
                    update_date=False,
                )
                for subnet_c in subnet_ab.subnets(new_prefix=prefix_len):
                    if (new_networks := test_for_new_networks(sql)) and subnet_ab_str not in new_networks:
                        # To allow faster scanning of new networks
                        log.debug(f'Found new networks- stop scanning the {subnet_ab_str} and start scanning the new')
                        sql.update_table(
                            'b_networks',
                            ('status', ),
                            ('idle', ),
                            f"network='{subnet_ab_str}'",
                            update_date=False,
                        )
                        break
                    subnet_abc_str = str(subnet_c)
                    try:
                        found_hosts = scan_networks(sql, full_net_pattern=subnet_abc_str)
                        if found_hosts >= 0:
                            b_net_hosts_num[subnet_ab_str] += found_hosts
                        # sleep some time
                        log.info(f'sleep {Config.sleep_between_c_networks_scan} seconds after c network scan')
                        time.sleep(Config.sleep_between_c_networks_scan)
                    except Exception as err:
                        log.exception(f'ERROR! exception while running scan_networks {subnet_abc_str}!', exc_info=err)

                # If nothing was found after full scanning subnet type B - it is marked and will never be scanned again
                current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
                b_hosts = b_net_hosts_num[subnet_ab_str]
                log.info(f'Found {b_hosts} hosts in "{subnet_ab_str}" B network')
                sql.update_table(
                    'b_networks',
                    ('network', 'hosts', 'updated', 'status'),
                    (subnet_ab_str, b_hosts, current_date, 'idle'),
                    f"network='{subnet_ab_str}'"
                )
                found_all += b_hosts
        except Exception as ex:
            log.exception("ERROR! Exception in while loop", exc_info=True)
            sys.exit(1)
        log.info(f'Found all {found_all} hosts during current scan')
    sys.exit(0)
