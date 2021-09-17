from flask import current_app
from rfapi.error import AuthenticationError, Error, HttpError
from rfapi import ConnectApiClient

from api.utils import catch_ssl_errors
from api.errors import AuthorizationError, RecordedFutureError


INVALID_API_KEY = 'Invalid API key'


class RecordedFutureClient(ConnectApiClient):

    def __init__(self, api_key):
        self.fields = current_app.config['SEARCH_FIELDS']
        super().__init__(api_key)
        self._request_session.headers['User-Agent'] = \
            current_app.config['USER_AGENT']

    def _request(self, lookup, observable):
        value = observable['value']
        return lookup(value, fields=self.fields)

    @catch_ssl_errors
    def make_observe(self, observable):
        expected_errors = (
            AuthenticationError,
            UnicodeEncodeError,
        )
        type_ = observable['type']
        lookups = {
            'ip': self.lookup_ip,
            'ipv6': self.lookup_ip,
            'domain': self.lookup_domain,
            'url': self.lookup_url,
            'sha1': self.lookup_hash,
            'sha256': self.lookup_hash,
            'md5': self.lookup_hash
        }
        try:
            result = self._request(lookups[type_], observable)
        except expected_errors:
            raise AuthorizationError(INVALID_API_KEY)
        except HttpError:
            result = {}
        except Error as error:
            raise RecordedFutureError(error.args[0])
        return result
