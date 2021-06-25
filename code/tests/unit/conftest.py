from datetime import datetime
from http import HTTPStatus
from unittest.mock import MagicMock

from pytest import fixture
import jwt

from api.errors import INVALID_ARGUMENT
from app import app
from tests.unit.payloads_for_tests import PRIVATE_KEY


@fixture(scope='session')
def client():
    app.rsa_private_key = PRIVATE_KEY

    app.testing = True

    with app.test_client() as client:
        yield client


@fixture(scope='session')
def valid_jwt(client):
    def _make_jwt(
            key='some_key',
            jwks_host='visibility.amp.cisco.com',
            aud='http://localhost',
            kid='02B1174234C29F8EFB69911438F597FF3FFEE6B7',
            wrong_structure=False
    ):
        payload = {
            'key': key,
            'jwks_host': jwks_host,
            'aud': aud,
        }

        if wrong_structure:
            payload.pop('key')

        return jwt.encode(
            payload, client.application.rsa_private_key, algorithm='RS256',
            headers={
                'kid': kid
            }
        )

    return _make_jwt


@fixture(scope='module')
def invalid_json_expected_payload():
    def _make_message(message):
        return {
            'errors': [{
                'code': INVALID_ARGUMENT,
                'message': message,
                'type': 'fatal'
            }]
        }

    return _make_message


def mock_api_response(status_code=HTTPStatus.OK, payload=None):
    mock_response = MagicMock()

    mock_response.status_code = status_code
    mock_response.ok = status_code == HTTPStatus.OK

    mock_response.json = lambda: payload

    return mock_response


def base_payload():
    return {
        "data": {
            "indicators": {
                "count": 2,
                "docs": [
                    {
                        "confidence": "High",
                        "description": "2 sightings on 1 source: Insikt Group."
                                       " 2 reports including Partial List of D"
                                       "ecoded Domains Linked to SUNBURST C2 C"
                                       "ommunications. Most recent link (Dec 2"
                                       "2, 2020): https://app.recordedfuture.c"
                                       "om/live/sc/52qYMuHmYqU1",
                        "id": "transient:indicator-ca332260-0585-4e36-a2dd-5f3"
                              "483d67226",
                        "producer": "Recorded Future",
                        "schema_version": "1.1.6",
                        "severity": 'Low',
                        "short_description": "Historically Referenced by Insik"
                                             "t Group",
                        "source": "Recorded Future Intelligence Card",
                        "source_uri": "https://app.recordedfuture.com/live/sc/"
                                      "entity/idn%3Acisco.com",
                        "timestamp":
                            f"{datetime.now().isoformat(timespec='seconds')}Z",
                        "title": "Historically Referenced by Insikt Group",
                        "type": "indicator",
                        "valid_time": {
                            "end_time": "2525-01-01T00:00:00Z",
                            "start_time": "2009-05-26T12:15:30.000Z"
                        }
                    },
                    {
                        "confidence": "High",
                        "description": "1 sighting on 1 source: Recorded Futur"
                                       "e Analyst Community Trending Indicator"
                                       "s. Recently viewed by many analysts in"
                                       " many organizations in the Recorded Fu"
                                       "ture community.",
                        "id": "transient:indicator-d89fb782-76d0-41aa-b373-99e"
                              "eb9ab3cb7",
                        "producer": "Recorded Future",
                        "schema_version": "1.1.6",
                        "severity": 'Low',
                        "short_description": "Trending in Recorded Future Anal"
                                             "yst Community",
                        "source": "Recorded Future Intelligence Card",
                        "source_uri": "https://app.recordedfuture.com/live/sc/"
                                      "entity/idn%3Acisco.com",
                        "timestamp":
                            f"{datetime.now().isoformat(timespec='seconds')}Z",
                        "title": "Trending in Recorded Future Analyst "
                                 "Community",
                        "type": "indicator",
                        "valid_time": {
                            "end_time": "2525-01-01T00:00:00Z",
                            "start_time": "2009-05-26T12:15:30.000Z"
                        }
                    }
                ]
            },
            "sightings": {
                'count': 2,
                'docs': [
                    {
                        'confidence': 'High', 'count': 1,
                        'description': '2 sightings on 1 source: Insikt Group.'
                                       ' 2 reports including Partial List of '
                                       'Decoded Domains Linked to SUNBURST C2 '
                                       'Communications. Most recent link (Dec '
                                       '22, 2020): https://app.recordedfuture.'
                                       'com/live/sc/52qYMuHmYqU1',
                        'id': 'transient:sighting-883b44a8-b131-41aa-a7d6-005b'
                              '1f1adb8d',
                        'internal': False,
                        'observables': [None],
                        'observed_time': {
                            'end_time': '2525-01-01T00:00:00Z',
                            'start_time': "2009-05-26T12:15:30.000Z"
                        },
                        'producer': 'Recorded Future',
                        'schema_version': '1.1.6',
                        'severity': 'Low',
                        'short_description': 'Historically Referenced by '
                                             'Insikt Group',
                        'source': 'Recorded Future Intelligence Card',
                        'source_uri': 'https://app.recordedfuture.com/live/'
                                      'sc/entity/idn%3Acisco.com',
                        'timestamp':
                            f"{datetime.now().isoformat(timespec='seconds')}Z",
                        'title': 'Historically Referenced by Insikt Group',
                        'type': 'sighting'
                    },
                    {
                        'confidence': 'High',
                        'count': 1,
                        'description': '1 sighting on 1 source: Recorded '
                                       'Future Analyst Community '
                                       'Trending Indicators. Recently viewed '
                                       'by many analysts in many '
                                       'organizations in the Recorded Future '
                                       'community.',
                        'id': 'transient:sighting-55282619-04f6-4167-af33-'
                              '593684f86a39',
                        'internal': False,
                        'observables': [None],
                        'observed_time': {
                            'end_time': '2525-01-01T00:00:00Z',
                            'start_time': "2009-05-26T12:15:30.000Z"
                        },
                        'producer': 'Recorded Future',
                        'schema_version': '1.1.6',
                        'severity': 'Low',
                        'short_description': 'Trending in Recorded Future '
                                             'Analyst Community',
                        'source': 'Recorded Future Intelligence Card',
                        'source_uri': 'https://app.recordedfuture.com/live/'
                                      'sc/entity/idn%3Acisco.com',
                        'timestamp':
                            f"{datetime.now().isoformat(timespec='seconds')}Z",
                        'title': 'Trending in Recorded Future Analyst '
                                 'Community',
                        'type': 'sighting'
                    }
                ]
            }
        }
    }


@fixture(scope='module')
def ssl_error_expected_relay_response():
    return {
        'errors':
            [
                {
                    'code': 'unknown',
                    'message':
                        'Unable to verify SSL certificate: '
                        'self signed certificate',
                    'type': 'fatal'
                }
            ]
    }


@fixture
def mock_exception_for_ssl_error():
    mock_response = MagicMock()
    mock_response.reason.args.__getitem__().verify_message = 'self signed' \
                                                             ' certificate'
    return mock_response


def mock_valid_time():
    return {
        'end_time': '2525-01-01T00:00:00Z',
        'start_time': '2009-05-26T12:15:30.000Z'
    }
