from http import HTTPStatus
from unittest.mock import patch

from pytest import fixture
from requests.exceptions import SSLError

from ..conftest import (
    mock_api_response,
    base_payload
)
from ..payloads_for_tests import (
    EXPECTED_RESPONSE_OF_JWKS_ENDPOINT,
    EXPECTED_RESPONSE_FROM_RECORDED_FUTURE
)
from .utils import get_headers


def routes():
    yield '/observe/observables'


def ids():
    yield 'ca332260-0585-4e36-a2dd-5f3483d67226'
    yield '883b44a8-b131-41aa-a7d6-005b1f1adb8d'
    yield 'd89fb782-76d0-41aa-b373-99eeb9ab3cb7'
    yield '55282619-04f6-4167-af33-593684f86a39'


@fixture(scope='module', params=routes(), ids=lambda route: f'POST {route}')
def route(request):
    return request.param


@fixture(scope='module')
def invalid_json_value():
    return [{'type': 'ip', 'value': ''}]


@patch('requests.get')
def test_enrich_call_with_valid_jwt_but_invalid_json_value(
        mock_request,
        route, client, valid_jwt, invalid_json_value,
        invalid_json_expected_payload
):
    mock_request.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    response = client.post(route,
                           headers=get_headers(valid_jwt()),
                           json=invalid_json_value)
    assert response.status_code == HTTPStatus.OK
    assert response.json == invalid_json_expected_payload(
        "{0: {'value': ['Field may not be blank.']}}"
    )


@fixture(scope='module')
def valid_json():
    return [{'type': 'domain', 'value': 'cisco.com'}]


@patch('api.utils.uuid4')
@patch('api.client.RecordedFutureClient.make_observe')
@patch('requests.get')
def test_enrich_call_success(mock_get, mock_request, mock_id,
                             client, route, valid_jwt, valid_json):
    mock_request.side_effect = [EXPECTED_RESPONSE_FROM_RECORDED_FUTURE]
    mock_get.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_id.side_effect = ids()
    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == base_payload()


@patch('api.client.RecordedFutureClient._request')
@patch('requests.get')
def test_enrich_call_with_ssl_error(mock_get, mock_request,
                                    mock_exception_for_ssl_error,
                                    client, route, valid_jwt, valid_json,
                                    ssl_error_expected_relay_response):

    mock_get.return_value = \
        mock_api_response(payload=EXPECTED_RESPONSE_OF_JWKS_ENDPOINT)
    mock_request.side_effect = [SSLError(mock_exception_for_ssl_error)]

    response = client.post(route, headers=get_headers(valid_jwt()),
                           json=valid_json)
    assert response.status_code == HTTPStatus.OK
    assert response.json == ssl_error_expected_relay_response
