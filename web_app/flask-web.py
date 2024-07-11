from pathlib import Path
import sys
import logging
import ipaddress
import json
import re
from urllib.parse import unquote_plus
from flask import (Flask, render_template, request, jsonify)

sys.path.insert(0, Path(__file__).parent)
from sql_connection import SqlConnection
from configuration import Config

logger = logging.getLogger('flask-web')
log_file = Path(Config.log_files_path) / f'{Path(__file__).stem}.log'
Config.config_logger(file=log_file)

show_list = ['ipv4', 'name', 'os', 'owner', 'status', 'type', 'productType', 'version',
             'updated',  'ssh', 'http', 'rdp', 'https', 'description']
search_params = ['ipv4', 'name', 'os', 'owner', 'status', 'type', 'version', 'HA', 'productType', 'updated', ]

params_attr = {
    'ipv4': "size: '120px', style: 'font-weight: bold;  color: blue', info: true,",
    'name': "size: '150px',",
    'updated': "size: '150px',",
    'type': "size: '60px',",
    'os': "size: '100px',",
    'owner': "size: '100px', editable: {type: 'text'},",
    'status': "size: '50px',",
    'productType': "size: '100px',",
    'version': "size: '100px',",
    'rdp': "size: '40px', attr: 'align=center',",
    'ssh': "size: '40px', attr: 'align=center',",
    'http': "size: '40px', attr: 'align=center',",
    'https': "size: '50px', attr: 'align=center',",
    'description': "size: '120px', attr: 'align=left', editable: {type: 'text'},",
    }

default_attr = "size: '80px',"
app = Flask(__name__)


@app.route('/details')
def details():
    ipv4 = request.args['ip']
    # sql = SqlConnection()
    # result = sql.cursor.execute(f'SELECT name,owner,type,os,version FROM hosts WHERE ipv4="{ipv4}"').fetchall()
    return render_template(
        'DetailsSummary.html',
        host_details=f'{ipv4}',
        host_links=f'host links {ipv4}',
        audc_summary='Summary'
    )


@app.route('/hosts/_action')
def table_action_hosts():
    return treat_action('hosts', request.args['request'])


@app.route('/b_networks/_action')
def table_action_bnetworks():
    return treat_action('b_networks', request.args['request'])


def treat_action(table, request):
    logger.debug(f'{table=}, {request=}')
    request_dict = json.loads(request)
    sql = SqlConnection()
    action = request_dict['action']
    if action == 'save':
        for host in request_dict['changes']:
            if table == 'hosts':
                sql_filter = f"ipv4 = '{host['recid']}'"
            elif table == 'b_networks':
                try:
                    net: ipaddress.IPv4Network = ipaddress.IPv4Network(host['recid'])
                except ValueError as ex:
                    logger.error(ex)
                    return str(ex), 500
                sql_filter = f"network = '{host['recid']}'"
            else:
                msg: str = f'Wrong table {table}'
                logger.error(msg)
                return msg, 500
            del host['recid']
            sql.update_table(
                table,
                [*host],
                [host[key] for key in host],
                sql_filter,
            )
    elif action == 'delete':
        for host in request_dict["recid"]:
            logger.debug(f'{action=}, "{host=}"')
            if table == 'hosts':
                sql.delete_host(host)
            elif table == 'b_networks':
                sql.delete_row('b_networks', f'network="{host}"')
    else:
        msg: str = f'Wrong action {request_dict["action"]}'
        logger.error(msg)
        return msg, 503
    return jsonify({"status": "success"}), 200


@app.route('/data/b_networks')
def get_b_networks():
    """ That works with json uploaded dynamically - not in use now """
    sql = SqlConnection()
    headers = sql.get_table_header('b_networks')
    hosts = sql.get_all_rows_in_table('b_networks')
    count = 1
    records_list = []
    for host in hosts:
        l_dict = dict(zip(headers, host))
        l_dict['recid'] = count
        records_list.append(l_dict)
        count += 1
    records = {'total': count, 'records': records_list}
    return json.dumps(records)


@app.route('/tables/<path:table_name>')
def tables(table_name=None):
    valid_tables = ('b_networks', 'alive_networks', 'applications')
    if table_name not in valid_tables:
        msg: str = f'Wrong table "{table_name}". Available tables: {valid_tables}'
        logger.error(msg)
        return msg, 500
    sql = SqlConnection()
    headers = sql.get_table_header(table_name)
    columns = []
    for header in headers:
        temp_str = f"field: '{header}', text: '{header.title()}', {params_attr.get(header, default_attr)} sortable: true"
        if header == 'hosts':
            temp_str += ", editable: {type: 'text'}"
        columns.append(f"{{ {temp_str} }}")

    columns_str = ',\n'.join(columns)
    rows = sql.get_all_rows_in_table(table_name)
    count = 1
    records = []
    search_list = []
    for host in rows:
        network = host[0]
        line = f"recid: '{network}'," + ', '.join([f"{param_name}: '{param}'" for param_name, param in zip(headers, host)])
        records.append(f"{{{line}}}")
        count += 1
    records_str = 'records: [' + ',\n'.join(records) + ']'
    for header in headers:
        search_list.append(f"{{field: '{header}', label: '{header.title()} ', type: 'text', operator: 'contains'}}")
    search_str = ',\n'.join(search_list)
    return render_template(
        'index_w2grid.html',
        columns_str=columns_str,
        records_str=records_str,
        search_str=search_str,
        action_page='/' + table_name,
    )


@app.route('/_add_new', methods=['GET', 'POST'])
def _add_new():
    # Assuming 'response' is the URL encoded string
    # decoded_response = unquote(response)
    logger.debug(request.method + f', {request.args=}')
    if request.method == 'POST':
        req_json = re.sub(r'request=', '', unquote_plus(request.get_data(as_text=True,)))
        data = json.loads(req_json.lower())['record']
        logger.debug(request.method + f', {data=}')
        sql = SqlConnection()
        if 'ipv4' in data:
            data['status'] = 'down'
            data['scanned'] = '0'
            sql.update_hosts_table(data)
        elif 'network' in data:
            try:
                net: ipaddress.IPv4Network = ipaddress.IPv4Network(data["network"])
            except ValueError as ex:
                msg: str = f'Wrong IP network format "{data["network"]}": {ex}'
                logger.error(msg)
                return jsonify({"status": "error",  "message": msg}), 200
            if net.prefixlen < 16:
                msg: str = f'Network prefix should be 16 or more'
                logger.error(msg)
                return jsonify({"status": "error",  "message": msg}), 200
            sql.update_table(
                'b_networks',
                [*data], [data[key] for key in data], f'network = "{net}"'
            )
        else:
            msg: str = f'Unknown data type'
            logger.error(msg)
            return jsonify({"status": "error",  "message": msg}), 200
        logger.debug(f'{data}, \n{[*data]}')
        return jsonify({"status": "success"}), 200
    else:
        match request.args['page']:
            case '/hosts':
                fields_str = """
                    {name: 'Owner', type: 'text', required: true},
                    {name: 'Ipv4', type: 'text', required: true},
                    {name: 'Name', type: 'text', required: false},
                    {name: 'Description', type: 'text'}
                """
                cancel_url = '/'
            case '/b_networks':
                fields_str = """
                    {name: 'Network', type: 'text', required: true},
                    {name: 'Owner', type: 'text', required: true}
                """
                cancel_url = '/tables/b_networks'
            case _:
                msg: str = f'Unknown page "{request.args["page"]}"'
                logger.error(msg)
                return msg, 500
        return render_template('add_new_record.html', fields_str=fields_str, cancel_url=cancel_url)


@app.route('/')
def index():
    sql = SqlConnection()
    #name = request.args.get('name')
    hosts = sql.get_hosts()
    headers = sql.get_hosts_ordered_header()

    columns = []
    for header in headers:
        hidden = 'true'
        if header in show_list: hidden = 'false'
        columns.append(f"{{ field: '{header}', text: '{header.title()}'," +
                       f" hidden: {hidden},{params_attr.get(header, default_attr)} sortable: true }}")
    columns_str = ',\n'.join(columns)

    records = []
    count = 0
    for host in hosts:
        line_list = []
        ipv4 = host[0]
        for param_name, param in zip(headers, host):
            if param_name == 'ipv4':
                #param = f'<a href="http://{param}">{param}</a>'
                #param = f'<b style="color:blue;">{param}</b>'
                line_list.append(f"{param_name}: '{param}'")
            elif isinstance(param, str):
                param = param[0:32]
                param = param.replace('\n', '')
                line_list.append(f"{param_name}: '{param}'")
            else:
                line_list.append(f"{param_name}: '{param}'")
        line = ', '.join(line_list)
        line = line.replace("'x'", "'&#10060;'")
        line = line.replace("'ok'", "'&#9989;'")
        line = line.replace("'down'", "'&#9760;'")
        line = line.replace("'up'", "'&#9989;'")

        records.append(f"{{recid: '{ipv4}', {line}}}")
        count += 1
    records_str = 'records: [' + ',\n'.join(records) + ']'

    search_list = []
    for search in search_params:
        if search == 'status':
            search_list.append(f"{{field: '{search}', label: '{search.title()} ', type: 'list', operator: 'is', \
options: {{items: ['&#9989;', '&#9760;']}} }}")
        else:
            search_list.append(f"{{field: '{search}', label: '{search.title()} ', type: 'text', operator: 'contains'}}")
    search_str = ',\n'.join(search_list)
    return render_template(
        'index_w2grid.html',
        columns_str=columns_str,
        records_str=records_str,
        search_str=search_str,
        action_page='/hosts'
    )


if __name__ == '__main__':
    try:
        app.run(debug=True, host='0.0.0.0', port=str(Config.web_app_port))
    except Exception as ex:
        logger.exception('An exception happened during running Flask app', exc_info=ex)
