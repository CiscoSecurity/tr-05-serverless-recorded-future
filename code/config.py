import json


class Config:
    settings = json.load(open('container_settings.json', 'r'))
    VERSION = settings["VERSION"]
    RECORDED_FUTURE_API_URL = 'https://api.recordedfuture.com/v2'

    RECORDED_FUTURE_HEALTH_CHECK_OBSERVABLE = {
        'type': 'ip',
        'value': '1.1.1.1'
    }

    RECORDED_FUTURE_SEARCH_FIELDS = 'risk,intelCard,sightings,entity,' \
                                    'timestamps'
