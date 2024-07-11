from waitress import serve
import flask_web
serve(flask_web.app, host='0.0.0.0', port=5000)