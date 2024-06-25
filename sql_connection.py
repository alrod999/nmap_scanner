import sqlite3
from datetime import datetime
import logging
import configuration as cfg

log = logging.getLogger('sql')


class SqlConnection:

    def __init__(self, db='net_scan_data.db'):
        self.conn = sqlite3.connect(db)
        self.cursor = self.conn.cursor()
        self.cursor.execute("SELECT count(name) FROM sqlite_master WHERE type='table' AND name='hosts'")

        if self.cursor.fetchone()[0] == 0:
            log.info('CREATE new SQL table "hosts"')
            self.cursor.execute(f'''
                CREATE TABLE hosts ({", ".join(
                [f"{key} {cfg.sql_fields[key]}" for key in cfg.sql_fields]
            )})
            ''')

        if not self.cursor.execute('PRAGMA table_info(alive_networks)').fetchall():
            log.info('Create "alive_networks" table')
            self.cursor.execute(f'''
                CREATE TABLE alive_networks (network char(20) primary key, hosts integer, audc integer)
            ''')
        if not self.cursor.execute('PRAGMA table_info(b_networks)').fetchall():
            log.info('Create "b_networks" table')
            self.cursor.execute(f'''
                CREATE TABLE b_networks (network char(20) primary key, hosts integer, updated date
            ''')

    def update_hosts_table(self, host_obj, current_date=None, commit=True):
        if current_date is None:
            current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
        sql_params = ', '.join([f"{key}='{remove_bad_symbols(host_obj[key])}'" for key in host_obj])
        if not self.cursor.execute(
                f"UPDATE hosts SET {sql_params},updated='{current_date}' WHERE ipv4='{host_obj['ipv4']}'"
        ).rowcount:
            for key in cfg.fields_defaults:
                if not host_obj.get(key): host_obj[key] = cfg.fields_defaults[key]
            sql_params = ', '.join([f"'{host_obj[key]}'" for key in host_obj])
            self.cursor.execute(
                f"INSERT INTO hosts ({', '.join([*host_obj])}, updated) VALUES ({sql_params},'{current_date}')"
            )
        if commit:
            self.conn.commit()

    def update_alive_networks_table(self, network, count):
        updated = self.cursor.execute(
            f'UPDATE alive_networks SET hosts={count} WHERE network="{network}"').rowcount
        if not updated:
            self.cursor.execute(f'INSERT INTO alive_networks (network, hosts) VALUES ("{network}", {count})')
        self.conn.commit()

    def update_table(self, table, params_list, vals_list, filter, update_date=False):
        sql_params = ', '.join([f'{par}="{val}"' for par, val in zip(params_list, vals_list)])
        if update_date:
            current_date = datetime.now().strftime("%Y-%b-%d %H:%M:%S")
            sql_params += f",updated='{current_date}'"
        updated = self.cursor.execute(f'UPDATE {table} SET {sql_params} WHERE {filter}').rowcount
        if not updated:
            vals = ",".join([f'"{val}"' for val in vals_list])
            self.cursor.execute(f'INSERT INTO {table} ({",".join(params_list)}) VALUES ({vals})')
        self.conn.commit()

    def get_hosts(self, ordered=True):
        if ordered:
            return self.cursor.execute(f"SELECT {cfg.hosts_names_str} FROM hosts").fetchall()
        return self.cursor.execute("SELECT * FROM hosts").fetchall()

    def get_all_rows_in_table(self, table, ordered=True):
        if ordered and table == 'hosts':
            return self.cursor.execute(f"SELECT {cfg.hosts_names_str} FROM {table}").fetchall()
        return self.cursor.execute(f"SELECT * FROM {table}").fetchall()

    def get_table_header(self, table):
        return [cl for ind, cl, *rest in self.cursor.execute(f'PRAGMA table_info({table})').fetchall()]

    @staticmethod
    def get_hosts_ordered_header():
        return cfg.hosts_names_str.split(',')

    def __del__(self):
        self.conn.close()


def remove_bad_symbols(my_str):
    for char in [';', ':', '!', '*', "'", '&', '"', ',', '%']:
        my_str = my_str.replace(char, '')
    return my_str
