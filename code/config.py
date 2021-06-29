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

    SUPPORTED_TYPES = {
        'ip': 'IP',
        'ipv6': 'IPv6',
        'domain': 'domain',
        'url': 'URL',
        'sha1': 'SHA1',
        'sha256': 'SHA256',
        'md5': 'MD5'
    }

    REFER_URL = (
        'https://app.recordedfuture.com/'
        'live/?sc=entity&id={type}%3A{value}'
    )
