import re
import sqlite3
import logging
from datetime import datetime
from configuration import Config as cfg

log = logging.getLogger('sql_client')


class SqlConnection:

    def __init__(self, db='net_scan_data.db'):
        self.conn = sqlite3.connect(db, timeout=10)
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='hosts'")

        if self.cursor.fetchone()[0] == 0:
            log.info('CREATE new SQL table "hosts"')
            self.cursor.execute(f'''
                CREATE TABLE hosts ({", ".join(
                [f"{key} {cfg.sql_fields[key]}" for key in cfg.sql_fields]
            )})
            ''')
            self.conn.commit()

        if not self.cursor.execute('PRAGMA table_info(alive_networks)').fetchall():
            log.info('Create "alive_networks" table')
            self.cursor.execute(f'''
                CREATE TABLE alive_networks (network char(20) primary key, hosts integer, audc integer)
            ''')
            self.conn.commit()
        if not self.cursor.execute('PRAGMA table_info(b_networks)').fetchall():
            log.info('Create "b_networks" table')
            self.cursor.execute(f'''
                CREATE TABLE b_networks (network char(20) primary key, hosts integer, updated date, owner char(100), status char(20))
            ''')
            self.conn.commit()
        if not self.cursor.execute('PRAGMA table_info(applications)').fetchall():
            log.info('Create "applications" table')
            self.cursor.execute(f'''
                CREATE TABLE applications (application char(50) primary key, pid integer, updated integer)
            ''')
            self.conn.commit()

    def update_hosts_table(self, host_obj, current_date=None, commit=True):
        if current_date is None:
            current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
        sql_params_list = []
        for key in host_obj:
            delimiter = "'" if cfg.sql_fields[key] != 'int' else ""
            sql_params_list.append(f"{key}={delimiter}{remove_bad_symbols(host_obj[key])}{delimiter}")
        sql_params = ', '.join(sql_params_list)
        cmd = f"UPDATE hosts SET {sql_params},updated='{current_date}' WHERE ipv4='{host_obj['ipv4']}'"
        log.debug(cmd)
        if not self.cursor.execute(cmd).rowcount:
            for key in cfg.fields_defaults:
                if not host_obj.get(key): host_obj[key] = cfg.fields_defaults[key]
            sql_params = ', '.join([f"'{host_obj[key]}'" for key in host_obj])
            cmd: str = f"INSERT INTO hosts ({', '.join([*host_obj])}, updated) VALUES ({sql_params},'{current_date}')"
            log.debug(cmd)
            self.cursor.execute(cmd)
        if commit:
            self.conn.commit()

    def update_alive_networks_table(self, network, count):
        cmd: str = f'UPDATE alive_networks SET hosts={count} WHERE network="{network}"'
        log.debug(cmd)
        updated = self.cursor.execute(cmd).rowcount
        if not updated:
            cmd = f'INSERT INTO alive_networks (network, hosts) VALUES ("{network}", {count})'
            log.debug(cmd)
            self.cursor.execute(cmd)
        self.conn.commit()

    def update_table(self, table, params_list, vals_list, sql_filter: str = '', update_date: bool = False):
        sql_params = ', '.join([f'{par}="{val}"' for par, val in zip(params_list, vals_list)])
        if update_date:
            current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
            sql_params += f",updated='{current_date}'"
        sql_filter = re.sub(r'WHERE\s+', '', sql_filter, re.IGNORECASE)
        sql_filter_updated = f'WHERE {sql_filter}' if sql_filter else ''
        cmd: str = f'UPDATE {table} SET {sql_params} {sql_filter_updated}'
        log.debug(cmd)
        updated = self.cursor.execute(cmd).rowcount
        if not updated:
            vals = ",".join([f'"{val}"' for val in vals_list])
            params = ",".join(params_list)
            if sql_filter:
                if re.search(f'\s+OR\s+', sql_filter, re.IGNORECASE):
                    raise Exception(f'Cannot insert line with "OR" in filter: {sql_filter=}')
                iterator = iter(re.sub(r'\s+AND\s+', '=', sql_filter, re.IGNORECASE).split('='))
                for par, val in zip(iterator, iterator):
                    params += f',{par}'
                    vals += f',{val}'
            try:
                cmd = f'INSERT INTO {table} ({params}) VALUES ({vals})'
                log.debug(cmd)
                self.cursor.execute(cmd)
            except Exception as err:
                log.error(f'Error while inserting row, SQL command: INSERT INTO {table} ({params}) VALUES ({vals})')
                raise
        self.conn.commit()

    def get_hosts(self, ordered=True):
        if ordered:
            return self.cursor.execute(f"SELECT {cfg.hosts_names_str} FROM hosts").fetchall()
        return self.cursor.execute("SELECT * FROM hosts").fetchall()

    def get_all_rows_in_table(self, table, ordered=True, select: str = '', sql_filter: str = ''):
        sql_filter = re.sub(r'WHERE\s+', '', sql_filter, re.IGNORECASE)
        sql_filter = f'WHERE {sql_filter}' if sql_filter else ''
        if not select:
            select = cfg.hosts_names_str if table == 'hosts' and ordered else '*'
        return self.cursor.execute(f"SELECT {select} FROM {table} {sql_filter}").fetchall()

    def get_table_header(self, table):
        return [cl for ind, cl, *rest in self.cursor.execute(f'PRAGMA table_info({table})').fetchall()]

    @staticmethod
    def get_hosts_ordered_header():
        return cfg.hosts_names_str.split(',')

    def delete_row(self, table, sql_filter) -> None:
        cmd: str = f'DELETE FROM {table} WHERE {sql_filter}'
        log.debug(cmd)
        self.cursor.execute(cmd)
        self.conn.commit()

    def delete_host(self, ipv4) -> None:
        self.delete_row('hosts', f'ipv4="{ipv4}"')

    def __del__(self):
        if self.conn:
            self.conn.close()


def remove_bad_symbols(my_str):
    for char in [';', ':', '!', '*', "'", '&', '"', ',', '%']:
        my_str = my_str.replace(char, '')
    return my_str
