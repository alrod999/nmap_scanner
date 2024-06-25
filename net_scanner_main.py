import time
from datetime import datetime
from multiprocessing import Process
import configuration as cfg
from sql_connection import SqlConnection
from refresher import search_for_dead
from scanner import scan_networks
from audc_scanner import run_audc_scanner


if __name__ == '__main__':
    log = cfg.config_logger(cfg.log_file, logger_name='main')
    print_original = print

    def print(msg, *args, **kwargs):
        log.info(msg, *args, **kwargs)

    # Spawn the hosts refresher (a scanner
    p_refresher = Process(target=search_for_dead,)
    p_refresher.daemon = True
    p_refresher.start()

    # Spawn the AUDC boards scanner-refresher
    p_audc_scanner = Process(target=run_audc_scanner,)
    p_audc_scanner.daemon = True
    p_audc_scanner.start()

    #p.join()

    sql = SqlConnection()
    alive_net_refresh_timer = time.time() + cfg.alive_net_refresh_period
    while True:
        try:
            if not cfg.ALLOW_SCAN:
                time.sleep(1)
                continue
            b_net_hosts_num = {}
            found_all = 0
            for subnet_a in cfg.networks_A_list:
                for subnet_b in cfg.get_b_network_for_scan(256):
                    if isinstance(subnet_b, int):
                        subnet_ab_str = f'{subnet_a}.{subnet_b}'
                    else:
                        subnet_ab_str = subnet_b
                    log.info(f'start scanning the "{subnet_ab_str}" B network')
                    sql_cmd = f'SELECT hosts FROM b_networks WHERE network="{subnet_ab_str}"'
                    b_hosts = sql.cursor.execute(sql_cmd).fetchone()
                    # (?) After the first scan filter empty B-networks
                    if b_hosts is not None and b_hosts[0] == 0:
                        log.info(f'the B subnet "{subnet_ab_str}." was detected as empty - will not be scanned')
                        continue
                    if not cfg.ipaddress.ip_network(f'{subnet_ab_str}.0.0/16').is_private:
                        log.info(f'The network {subnet_ab_str}.0.0/16 is not private - cannot run scan on public networks')
                        continue
                    b_net_hosts_num[subnet_ab_str] = 0
                    for subnet_c in range(0, 256):
                        subnet_abc_str = f'{subnet_ab_str}.{subnet_c}.0/16'
                        try:
                            found_hosts = scan_networks(sql, full_net_pattern=f'{subnet_ab_str}.{subnet_c}.0/24')
                            if found_hosts >= 0:
                                b_net_hosts_num[subnet_ab_str] += found_hosts
                            # sleep some time
                            log.info(f'sleep {cfg.sleep_between_c_networks_scan} seconds after c network scan')
                            time.sleep(cfg.sleep_between_c_networks_scan)

                            # It is most probable to find new host in alive networks
                            # So the "alive" subnets "C" are scanned more frequently
                            if alive_net_refresh_timer < time.time():
                                log.info("Start scanning the 'alive_networks'")
                                alive_net_refresh_timer = time.time() + cfg.alive_net_refresh_period
                                # To limit scanning - limit the scan to "selected" networks
                                for network, in sql.cursor.execute('SELECT network FROM alive_networks').fetchall():
                                    if (cfg.scan_mode != cfg.ScanMode.SELECTED or
                                            '.'.join(network.split('.')[0:1]) not in cfg.selected_b_networks):
                                        scan_networks(sql, full_net_pattern=network)
                                    else:
                                        log.debug(f'The "{network}" is not part of selected_b_networks - will not be scanned')
                        except Exception as err:
                            log.critical(f'ERROR! exception while running scan_networks {subnet_abc_str}!', exc_info=err)

                    # If nothing was found after full scanning subnet type B - it is marked and will never be scanned again
                    current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
                    b_hosts = b_net_hosts_num[subnet_ab_str]
                    log.info(f'Found {b_hosts} hosts in "{subnet_ab_str}" B network')
                    sql.update_table(
                        'b_networks',
                        ('network', 'hosts', 'updated'),
                        (subnet_ab_str, b_hosts, current_date),
                        f"network='{subnet_ab_str}'"
                    )
        except Exception as ex:
            log.exception("ERROR! Exception in while loop", exc_info=True)
            exit(1)
        log.info(f'Found all {found_all} hosts during current scan')

    exit(0)
