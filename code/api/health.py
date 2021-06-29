from flask import Blueprint
from flask import current_app

from api.utils import get_jwt, jsonify_data
from api.client import RecordedFutureClient

health_api = Blueprint('health', __name__)


@health_api.route('/health', methods=['POST'])
def health():
    api_key = get_jwt()
    client = RecordedFutureClient(api_key)
    _ = client.make_observe(current_app.config['HEALTH_CHECK_OBSERVABLE'])

    return jsonify_data({'status': 'ok'})
