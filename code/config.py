import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]

    HEALTH_CHECK_OBSERVABLE = {
        'type': 'ip',
        'value': '1.1.1.1'
    }

    SEARCH_FIELDS = ('risk,intelCard,sightings,entity,'
                     'timestamps')

    USER_AGENT = (
        'SecureX Threat Response Integrations '
        '<tr-integrations-support@cisco.com>')

    CTR_DEFAULT_ENTITIES_LIMIT = 100

    HUMAN_READABLE = 'human_readable'
    RECORDED_FUTURE = 'recorded_future'

    TYPES_FORMATS = {
        'ip': {
            HUMAN_READABLE: 'IP',
            RECORDED_FUTURE: 'ip'
        },
        'ipv6': {
            HUMAN_READABLE: 'IPv6',
            RECORDED_FUTURE: 'ip'
        },
        'domain': {
            HUMAN_READABLE: 'domain',
            RECORDED_FUTURE: 'idn'
        },
        'url': {
            HUMAN_READABLE: 'URL',
            RECORDED_FUTURE: 'url'
        },
        'sha1': {
            HUMAN_READABLE: 'SHA1',
            RECORDED_FUTURE: 'hash'
        },
        'sha256': {
            HUMAN_READABLE: 'SHA256',
            RECORDED_FUTURE: 'hash'
        },
        'md5': {
            HUMAN_READABLE: 'MD5',
            RECORDED_FUTURE: 'hash'
        }
    }

    REFER_URL = (
        'https://app.recordedfuture.com/'
        'live/?sc=entity&id={type}%3A{value}'
    )
