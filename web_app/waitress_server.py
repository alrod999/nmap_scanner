from waitress import serve
import sys
import logging
from pathlib import Path
base_dir = str(Path(__file__).parent.parent)
if base_dir not in sys.path: sys.path.append(base_dir)
from configuration import Config
import flask_web

if __name__ == '__main__':
    logger = logging.getLogger('waitress_server')
    try:
        serve(flask_web.app, host='0.0.0.0', port=Config.web_app_port, threads=4)
    except Exception as err:
        logger.exception('An exception happened during running Flask app', exc_info=err)
