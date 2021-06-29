from datetime import datetime, timedelta

from api.utils import transient_id, RangeDict

CTIM_DEFAULTS = {
    'schema_version': '1.1.6'
}

SOURCE = 'Recorded Future Intelligence Card'

INDICATOR = 'indicator'
SIGHTING = 'sighting'
RELATIONSHIP = 'relationship'

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

ENTITY_RELEVANCE_PERIOD = timedelta(days=30)


class Mapping:
    def __init__(self, observable):
        self.observable = observable
        self.index = None

    @staticmethod
    def time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    def _observables(self, lookup):
        return {
            'type': self.observable['type'],
            'value': lookup['data']['entity']['name']
        }

    def _valid_time(self, lookup):
        start_time = lookup['data']['timestamps']['firstSeen']
        end_time = datetime(2525, 1, 1)

        return {
            'start_time': start_time,
            'end_time': self.time_format(end_time)
        }

    def _sighting_start_time(self, lookup):
        # Iterate through corresponding evidenceDetails
        if self.index is None:
            self.index = 0
        else:
            self.index += 1
        return (
            lookup['data']
            ['risk']
            ['evidenceDetails']
            [self.index]['timestamp']
        )

    def _defaults(self, rule, lookup):
        return {
            **CTIM_DEFAULTS,
            'confidence': 'High',
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            'source': 'Recorded Future Intelligence Card',
            'source_uri': lookup['data'].get('intelCard'),
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
            'producer': 'Recorded Future',
            **self._defaults(rule, lookup)
        }

    def extract_sighting_of_an_indicator(self, lookup, rule):

        return {
            'id': transient_id(SIGHTING),
            'count': 1,
            'type': SIGHTING,
            'observed_time': {
                'start_time': self._sighting_start_time(lookup)
            },
            'severity': SIGHTING_SEVERITY[
                int(lookup['data']['risk']['score'])
            ],
            'internal': False,
            'observables': [self._observables(lookup)],
            **self._defaults(rule, lookup)
        }

    @staticmethod
    def extract_relationship(source_ref, target_ref, type_):
        return {
            'id': transient_id(RELATIONSHIP),
            'source_ref': source_ref,
            'target_ref': target_ref,
            'relationship_type': type_,
            'type': RELATIONSHIP,
            **CTIM_DEFAULTS
        }
