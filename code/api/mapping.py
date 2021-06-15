from datetime import datetime, timedelta

from api.utils import transient_id

CTIM_DEFAULTS = {
    'schema_version': '1.1.6'
}

SOURCE = 'Recorded Future Intelligence Card'

INDICATOR = 'indicator'

INDICATOR_DEFAULTS = {
    **CTIM_DEFAULTS,
    'type': INDICATOR,
    'confidence': 'High',
    'producer': 'Recorded Future',
}

ENTITY_RELEVANCE_PERIOD = timedelta(days=30)


class Mapping:
    def __init__(self, observable):
        self.observable = observable

    @staticmethod
    def time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    @staticmethod
    def _valid_time(lookup):
        start_time = lookup['data']['timestamps']['firstSeen']
        end_time = datetime(2525, 1, 1)

        return {
            'start_time': start_time,
            'end_time': end_time
        }

    def extract_indicator(self, lookup, rule):
        return {
            'id': transient_id(INDICATOR),
            'valid_time': self._valid_time(lookup),
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            'severity': rule['criticality'],
            'source': 'Recorded Future Intelligence Card',
            'source_uri': lookup['data']['intelCard'],
            'timestamp': self.time_format(datetime.now()),
            **INDICATOR_DEFAULTS
        }
