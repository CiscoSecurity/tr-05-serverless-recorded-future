import requests

from flask import current_app

from api.utils import catch_ssl_errors


class RecordedFutureClient:
    def __init__(self, api_key):
        self.base_url = current_app.config['RECORDED_FUTURE_API_URL']
        self.headers = {
            'X-RFToken': api_key
        }
        self.fields = current_app.config['RECORDED_FUTURE_SEARCH_FIELDS']

    @catch_ssl_errors
    def _request(self, observable_type, value, params=None, headers=None):
        url = '/'.join([self.base_url, observable_type, value])

        response = requests.get(url, params=params, headers=headers)
        return response

    def make_observe(self, observable):
        params = {
            'metadata': False,
            'fields': self.fields
        }
        result = self._request(observable['type'], observable['value'],
                               params=params, headers=self.headers)
        return result.json()
