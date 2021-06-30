from datetime import datetime, timedelta

from api.utils import transient_id, RangeDict

CTIM_DEFAULTS = {
    'schema_version': '1.1.6'
}

SOURCE = 'Recorded Future Intelligence Card'

INDICATOR = 'indicator'
SIGHTING = 'sighting'
RELATIONSHIP = 'relationship'
JUDGEMENT = 'judgement'

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

JUDGEMENT_SEVERITY = RangeDict({
    range(3, 5): 'High',
    range(2, 3): 'Medium',
    range(1, 2): 'Low',
    range(0, 1): None,
})

JUDGEMENT_DISPOSITION_NAME = RangeDict({
    range(3, 5): 'Malicious',
    range(2, 3): 'Suspicious',
    range(1, 2): 'Common',
    range(0, 1): 'Unknown',
})

ENTITY_RELEVANCE_PERIOD = timedelta(days=30)


class Mapping:
    def __init__(self, observable):
        self.observable = observable

    @staticmethod
    def time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    @staticmethod
    def _sighting_start_time(lookup, index):
        return (
            lookup['data']
            ['risk']
            ['evidenceDetails']
            [index]['timestamp']
        )

    def _observables(self, lookup):
        return {
            'type': self.observable['type'],
            'value': lookup['data']['entity']['name']
        }

    def _valid_time(self, lookup, entity):
        if entity == 'judgement':
            start_time = self.time_format(datetime.utcnow())
            if lookup['data']['entity']['type'] == 'Hash':
                end_time = datetime(2525, 1, 1)
            else:
                end_time = datetime.fromisoformat(start_time[:-1]) \
                           + ENTITY_RELEVANCE_PERIOD
        else:
            start_time = lookup['data']['timestamps']['firstSeen']
            end_time = datetime(2525, 1, 1)

        return {
            'start_time': start_time,
            'end_time': self.time_format(end_time)
        }

    def extract_indicator(self, lookup, rule):
        return {
            'id': transient_id(INDICATOR),
            'type': INDICATOR,
            'valid_time': self._valid_time(lookup, INDICATOR),
            'severity': INDICATOR_SEVERITY[
                int(rule['criticality'])
            ],
            'source': 'Recorded Future Intelligence Card',
            'confidence': 'High',
            'producer': 'Recorded Future',
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            'source_uri': lookup['data']['intelCard'],
            'timestamp': self.time_format(datetime.utcnow()),
            **CTIM_DEFAULTS
        }

    def extract_sighting_of_an_indicator(self, lookup, rule, index=0):

        return {
            'id': transient_id(SIGHTING),
            'count': 1,
            'type': SIGHTING,
            'observed_time': {
                'start_time': self._sighting_start_time(lookup, index)
            },
            'severity': SIGHTING_SEVERITY[
                int(lookup['data']['risk']['score'])
            ],
            'confidence': 'High',
            'internal': False,
            'source': 'Recorded Future Intelligence Card',
            'observables': [self._observables(lookup)],
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            'source_uri': lookup['data']['intelCard'],
            'timestamp': self.time_format(datetime.utcnow()),
            **CTIM_DEFAULTS
        }

    def extract_sighting_of_an_observable(self, lookup, rule):
        source = lookup['data']['sightings']['source']
        return {
            'id': transient_id(SIGHTING),
            'count': 1,
            'type': SIGHTING,
            'observed_time': {
                'start_time': lookup['data']['sightings']['published']
            },
            'severity': SIGHTING_SEVERITY[
                int(lookup['data']['risk']['score'])
            ],
            'confidence': 'High',
            'internal': False,
            'observables': [self._observables(lookup)],
            'title': lookup['data']['sightings']['title'],
            'description': f'Seen by {source}',
            'short_description': rule['rule'],
            'source': source,
            'source_uri': lookup['data']['sightings']['url'],
            'timestamp': self.time_format(datetime.utcnow()),
            **CTIM_DEFAULTS
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

    def extract_judgement(self, lookup, rule):
        return {
            'id': transient_id(JUDGEMENT),
            'disposition': rule['criticality'],
            'disposition_name': JUDGEMENT_DISPOSITION_NAME[
                rule['criticality']
            ],
            'type': JUDGEMENT,
            'observable': self._observables(lookup),
            'priority': 90,
            'severity': JUDGEMENT_SEVERITY[rule['criticality']],
            'valid_time': self._valid_time(lookup, JUDGEMENT),
            **CTIM_DEFAULTS
        }
