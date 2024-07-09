import time
import ipaddress
from datetime import datetime
from multiprocessing import Process
from configuration import Config, ScanMode
from sql_connection import SqlConnection
from refresher import search_for_dead
from scanner import scan_networks
from audc_scanner import run_audc_scanner

log = Config.config_logger(Config.log_file, logger_name='main')


def test_for_new_networks(sql_handler: SqlConnection) -> list[tuple]:
    return [el[0] for el in
            sql_handler.cursor.execute('SELECT network FROM b_networks WHERE updated is NULL').fetchall()]


def get_networks_for_scan(sql_handler: SqlConnection) -> list[str]:
    res: list[tuple]
    # Prioritize the networks that were not updated yet
    if res := test_for_new_networks(sql_handler):
        return res
    return [el[0] for el in sql_handler.cursor.execute('SELECT network FROM b_networks').fetchall()]


if __name__ == '__main__':

    # Spawn the hosts refresher (a scanner
    p_refresher = Process(target=search_for_dead,)
    p_refresher.daemon = True
    p_refresher.start()
    # Spawn the AUDC boards scanner-refresher
    p_audc_scanner = Process(target=run_audc_scanner,)
    p_audc_scanner.daemon = True
    p_audc_scanner.start()
    sql = SqlConnection()
    sql.update_table('b_networks', ('status',), ('idle',), update_date=False, )
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
            exit(1)
        log.info(f'Found all {found_all} hosts during current scan')
    exit(0)
