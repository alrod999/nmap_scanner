# nmap_scanner
A Python application that gathers and displays information about hosts within local networks.
The [nmap.exe](https://nmap.org/) is used to scan network(s).
The Web interface is built on the [Flask](https://flask.palletsprojects.com/) framework and [w2ui library](https://w2ui.com/web/)
The scanned data is stored in sqlite3 database.
The scanning is limited to private networks only!
The  scanning is focused on open ports (HTTP, HTTPS, SSH, RDP) and basic OS information.
