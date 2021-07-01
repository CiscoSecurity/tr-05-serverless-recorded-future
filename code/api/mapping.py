from datetime import datetime, timedelta

from api.utils import transient_id, RangeDict

CTIM_DEFAULTS = {
    'schema_version': '1.1.6'
}

CONFIDENCE = {
    'confidence': 'High'
}

SIGHTING_DEFAULTS = {
    'count': 1,
    'internal': False,
    **CONFIDENCE

}

SOURCE = 'Recorded Future Intelligence Card'

SIGHTING = 'sighting'
INDICATOR = 'indicator'
JUDGEMENT = 'judgement'
RELATIONSHIP = 'relationship'

SIGHTING_OF_INDICATOR = f'{SIGHTING}_of_{INDICATOR}'
SIGHTING_OF_OBSERVABLE = f'{SIGHTING}_of_observable'

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


def overwrite_root_class_name(func):
    def wraps(*args, **kwargs):
        args[0].root.name = args[0].name
        return func(*args, **kwargs)

    return wraps


def add_source_uri(func):
    def wraps(*args, **kwargs):
        result = func(*args, **kwargs)
        uri = args[0].root.source_uri(args[1])
        if uri:
            result['source_uri'] = uri
        return result

    return wraps


class Mapping:
    name = None

    def __init__(self, observable, lookup):
        self.observable = observable
        self.lookup = lookup
        self.indicator = self.Indicator(self)
        self.sighting_of_indicator = self.SightingOfIndicator(self)
        self.sighting_of_observable = self.SightingOfObservable(self)
        self.judgement = self.Judgement(self)
        self.relationship = self.Relationship()

    @staticmethod
    def time_format(time):
        return f'{time.isoformat(timespec="seconds")}Z'

    def source(self, index=0):
        source = 'Recorded Future Intelligence Card'
        sources = {
            INDICATOR:
                lambda: source,
            SIGHTING_OF_INDICATOR:
                lambda: source,
            JUDGEMENT:
                lambda: source,
            SIGHTING_OF_OBSERVABLE:
                lambda: self._sighting(index)['source']
        }
        return sources[self.name]()

    def source_uri(self, index=0):
        uri = {
            INDICATOR:
                lambda: self.lookup['data'].get('intelCard'),
            SIGHTING_OF_INDICATOR:
                lambda: self.lookup['data'].get('intelCard'),
            JUDGEMENT:
                lambda: self.lookup['data'].get('intelCard'),
            SIGHTING_OF_OBSERVABLE:
                lambda: self._sighting(index).get('url')
        }

        return uri[self.name]()

    def severity(self, index=0):
        severity = {
            INDICATOR:
                lambda: INDICATOR_SEVERITY[
                    int(self._evidence_detail(index)['criticality'])
                ],
            SIGHTING_OF_INDICATOR:
                lambda: SIGHTING_SEVERITY[
                    int(self.lookup['data']['risk']['score'])
                ],
            JUDGEMENT:
                lambda: JUDGEMENT_SEVERITY[
                    int(self._evidence_detail(index)['criticality'])
                ],
        }
        return severity[self.name]()

    def description(self, index=0):
        descriptions = {
            INDICATOR:
                lambda: self._evidence_detail(index)['evidenceString'],
            SIGHTING_OF_INDICATOR:
                lambda: self._evidence_detail(index)['evidenceString'],
            SIGHTING_OF_OBSERVABLE:
                lambda: f"Seen by {self._sighting(index)['source']}"
        }
        return descriptions[self.name]()

    def short_description(self, index=0):
        descriptions = {
            INDICATOR:
                lambda: self._evidence_detail(index)['rule'],
            SIGHTING_OF_INDICATOR:
                lambda: self._evidence_detail(index)['rule'],
            SIGHTING_OF_OBSERVABLE:
                lambda: f"Seen by {self._sighting(index)['source']}"
        }
        return descriptions[self.name]()

    def title(self, index=0):
        titles = {
            INDICATOR:
                lambda: self._evidence_detail(index)['rule'],
            SIGHTING_OF_INDICATOR:
                lambda: self._evidence_detail(index)['rule'],
            SIGHTING_OF_OBSERVABLE:
                lambda: self._sighting(index)['title']
        }
        return titles[self.name]()

    def observed_time(self, index=0):
        time = {
            SIGHTING_OF_INDICATOR:
                lambda: {
                    'start_time': self._evidence_detail(index)['timestamp']
                },
            SIGHTING_OF_OBSERVABLE:
                lambda: {
                    'start_time': self._sighting(index)['published']
                }
        }
        return time[self.name]()

    def observables(self):
        return {
            'type': self.observable['type'],
            'value': self.lookup['data']['entity']['name']
        }

    def valid_time(self, entity):
        if entity == 'judgement':
            start_time = self.time_format(datetime.utcnow())
            if self.lookup['data']['entity']['type'] == 'Hash':
                end_time = datetime(2525, 1, 1)
            else:
                end_time = datetime.fromisoformat(start_time[:-1]) \
                           + ENTITY_RELEVANCE_PERIOD
        else:
            start_time = self.lookup['data']['timestamps']['firstSeen']
            end_time = datetime(2525, 1, 1)

        return {
            'start_time': start_time,
            'end_time': self.time_format(end_time)
        }

    def _sighting(self, index):
        result = {}
        try:
            result = self.lookup['data']['sightings'][index]
        except IndexError:
            pass

        return result

    def _evidence_detail(self, index):
        result = {}
        try:
            result = self.lookup['data']['risk']['evidenceDetails'][index]
        except IndexError:
            pass

        return result

    class Indicator:
        name = INDICATOR

        def __init__(self, root):
            self.root = root

        @overwrite_root_class_name
        @add_source_uri
        def extract(self, index=0):
            return {
                'id': transient_id(INDICATOR),
                'type': INDICATOR,
                'valid_time': self.root.valid_time(INDICATOR),
                'severity': self.root.severity(index),
                'source': self.root.source(index),
                'producer': 'Recorded Future',
                'title': self.root.title(index),
                'description': self.root.description(index),
                'short_description': self.root.short_description(index),
                'timestamp': self.root.time_format(datetime.utcnow()),
                **CTIM_DEFAULTS,
                **CONFIDENCE
            }

    class SightingOfIndicator:
        name = SIGHTING_OF_INDICATOR

        def __init__(self, root):
            self.root = root

        @overwrite_root_class_name
        @add_source_uri
        def extract(self, index=0):
            return {
                'id': transient_id(SIGHTING),
                'type': SIGHTING,
                'observed_time': self.root.observed_time(index),
                'severity': self.root.severity(index),
                'source': self.root.source(index),
                'observables': [self.root.observables()],
                'title': self.root.title(index),
                'description': self.root.description(index),
                'short_description': self.root.short_description(index),
                'timestamp': self.root.time_format(datetime.utcnow()),
                **SIGHTING_DEFAULTS,
                **CTIM_DEFAULTS
            }

    class SightingOfObservable:
        name = SIGHTING_OF_OBSERVABLE

        def __init__(self, root):
            self.root = root

        @overwrite_root_class_name
        @add_source_uri
        def extract(self, index=0):
            sightings = self.root.lookup['data']['sightings']
            if sightings and index <= len(sightings) - 1:
                return {
                    'id': transient_id(SIGHTING),
                    'type': SIGHTING,
                    'observed_time': self.root.observed_time(index),
                    'source': self.root.source(index),
                    'observables': [self.root.observables()],
                    'title': self.root.title(index),
                    'description': self.root.description(index),
                    'short_description': self.root.short_description(index),
                    'timestamp': self.root.time_format(datetime.utcnow()),
                    **SIGHTING_DEFAULTS,
                    **CTIM_DEFAULTS
                }

    class Judgement:
        name = JUDGEMENT

        def __init__(self, root):
            self.root = root

        @overwrite_root_class_name
        @add_source_uri
        def extract(self, index=0):
            criticality = self.root._evidence_detail(index)['criticality']
            return {
                'id': transient_id(JUDGEMENT),
                'disposition': criticality,
                'disposition_name': JUDGEMENT_DISPOSITION_NAME[criticality],
                'type': JUDGEMENT,
                'observable': self.root.observables(),
                'priority': 90,
                'severity': self.root.severity(index),
                'valid_time': self.root.valid_time(JUDGEMENT),
                'timestamp': self.root.time_format(datetime.utcnow()),
                'source': self.root.source(index),
                **CTIM_DEFAULTS,
                **CONFIDENCE
            }

    class Relationship:
        name = RELATIONSHIP

        @staticmethod
        def extract(source_ref, target_ref, type_):
            return {
                'id': transient_id(RELATIONSHIP),
                'source_ref': source_ref,
                'target_ref': target_ref,
                'relationship_type': type_,
                'type': RELATIONSHIP,
                **CTIM_DEFAULTS
            }
