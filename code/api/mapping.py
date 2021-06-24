from datetime import datetime, timedelta

from api.utils import transient_id, RangeDict


CTIM_DEFAULTS = {
    'schema_version': '1.1.6'
}

SOURCE = 'Recorded Future Intelligence Card'

INDICATOR = 'indicator'
SIGHTING = 'sighting'

SIGHTING_SEVERITY = RangeDict({
    range(65, 100): "High",
    range(25, 65): "Medium",
    range(1, 25): "Low",
    range(0, 1): None,
})

INDICATOR_SEVERITY = RangeDict({
    range(3, 5): "High",
    range(2, 3): "Medium",
    range(1, 2): "Low",
    range(0, 1): None,
})

OBSERVABLES = {
    'IpAddress': 'ip',
    'InternetDomainName': 'domain'
}

ENTITY_RELEVANCE_PERIOD = timedelta(days=30)


class Mapping:
    def __init__(self, observable):
        self.observable = observable

    @staticmethod
    def time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    @staticmethod
    def _observables(lookup):
        if lookup['data']['entity']['type'] in OBSERVABLES.keys():
            return {
                'type': OBSERVABLES[lookup['data']['entity']['type']],
                'value': lookup['data']['entity']['name']
            }

    def _valid_time(self, lookup):
        start_time = lookup['data']['timestamps']['firstSeen']
        end_time = datetime(2525, 1, 1)

        return {
            'start_time': start_time,
            'end_time': self.time_format(end_time)
        }

    def _defaults(self, rule, lookup):
        return {
            **CTIM_DEFAULTS,
            'confidence': 'High',
            'producer': 'Recorded Future',
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            'source': 'Recorded Future Intelligence Card',
            'source_uri': lookup['data']['intelCard'],
            'timestamp': self.time_format(datetime.now())
        }

    def extract_indicator(self, lookup, rule):
        return {
            'id': transient_id(INDICATOR),
            'type': INDICATOR,
            'valid_time': self._valid_time(lookup),
            'severity': INDICATOR_SEVERITY[
                int(rule['criticality'])
            ],
            **self._defaults(rule, lookup)
        }

    def extract_sighting_of_an_indicator(self, lookup, rule):
        return {
            'id': transient_id(SIGHTING),
            'count': 1,
            'type': SIGHTING,
            'observed_time': self._valid_time(lookup),
            'severity': SIGHTING_SEVERITY[
                int(lookup['data']['risk']['score'])
            ],
            'internal': False,
            'observables': [self._observables(lookup)],
            **self._defaults(rule, lookup)
        }
