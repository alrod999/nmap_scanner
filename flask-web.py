import json
import os
from flask import Flask, render_template, request, jsonify
from sql_connection import SqlConnection
from configuration import config_logger, log_files_path

log_file = os.path.join(log_files_path, 'web_app.log')
config_logger(log_file, 'web_app')

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
    'description': "size: '120px', attr: 'align=left',",
    }

defaut_attr = "size: '80px',"

app = Flask(__name__)


@app.route('/details')
def details():
    ipv4 = request.args['ip']
    sql = SqlConnection()
    result = sql.cursor.execute(f'SELECT name,owner,type,os,version FROM hosts WHERE ipv4="{ipv4}"').fetchall()
    return render_template('DetailsSummary.html',
                           host_details=f'{ipv4}',
                           host_links=f'host links {ipv4}',
                           audc_summary='AUDC summary'
                           )


@app.route('/hosts/_action')
def table_action_hosts():
    return treat_action('hosts', request.args['request'])


@app.route('/b_networks/_action')
def table_action_bnetworks():
    return treat_action('b_networks', request.args['request'])


def treat_action(table, request):
    print(request)
    request_dict = json.loads(request)
    sql = SqlConnection()
    if request_dict['action'] == 'save':
        for host in request_dict['changes']:
            if table == 'hosts':
                filter = f"ipv4 = '{host['recid']}'"
            elif table == 'b_networks':
                filter = f"network = '{host['recid']}'"
            else:
                raise Exception(f'Wrong table {table}')

            del host['recid']
            sql.update_table(
                table,
                [*host],
                [host[key] for key in host],
                filter,
            )

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
    valid_tables = ('b_networks', 'alive_networks')
    if table_name is None or table_name == "" or table_name not in valid_tables:
        return f'\nWrong table "{table_name}".\n Available tables: "b_networks", "alive_networks"'
    sql = SqlConnection()
    headers = sql.get_table_header(table_name)
    columns = []
    for header in headers:
        temp_str = f"field: '{header}', text: '{header.title()}', {params_attr.get(header, defaut_attr)} sortable: true"
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
        action_page=table_name,
    )


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
                       f" hidden: {hidden},{params_attr.get(header, defaut_attr)} sortable: true }}")
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
        action_page='hosts'
    )


if __name__ == '__main__':
    app.run(debug=True)
