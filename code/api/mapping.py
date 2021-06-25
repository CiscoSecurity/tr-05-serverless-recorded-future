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

OBSERVABLES = {
    'IpAddress': 'ip',
    'InternetDomainName': 'domain',
    'Hash': 'hash'
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
        type_ = lookup['data']['entity']['type']
        if type_ in OBSERVABLES.keys():
            return {
                'type': OBSERVABLES[type_],
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

    def _defaults(self, lookup):
        return {
            **CTIM_DEFAULTS,
            'confidence': 'High',
            'source': 'Recorded Future Intelligence Card',
            'source_uri': lookup['data']['intelCard'],
            'timestamp': self.time_format(datetime.utcnow())
        }

    def extract_indicator(self, lookup, rule):
        return {
            'id': transient_id(INDICATOR),
            'type': INDICATOR,
            'valid_time': self._valid_time(lookup, INDICATOR),
            'severity': INDICATOR_SEVERITY[
                int(rule['criticality'])
            ],
            'producer': 'Recorded Future',
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            **self._defaults(lookup)
        }

    def extract_sighting_of_an_indicator(self, lookup, rule):
        return {
            'id': transient_id(SIGHTING),
            'count': 1,
            'type': SIGHTING,
            'observed_time': self._valid_time(lookup, SIGHTING),
            'severity': SIGHTING_SEVERITY[
                int(lookup['data']['risk']['score'])
            ],
            'internal': False,
            'observables': [self._observables(lookup)],
            'title': rule['rule'],
            'description': rule['evidenceString'],
            'short_description': rule['rule'],
            **self._defaults(lookup)
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
            **self._defaults(lookup)
        }
