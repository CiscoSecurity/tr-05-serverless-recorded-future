from functools import partial

from flask import Blueprint, g, current_app

from api.mapping import Mapping
from api.utils import filter_observables
from api.schemas import ObservableSchema
from api.client import RecordedFutureClient
from api.utils import get_json, get_jwt, jsonify_data, jsonify_result


enrich_api = Blueprint('enrich', __name__)

get_observables = partial(get_json, schema=ObservableSchema(many=True))


@enrich_api.route('/deliberate/observables', methods=['POST'])
def deliberate_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data({})


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    api_key = get_jwt()
    observables = filter_observables(get_observables())

    g.indicators = []
    g.sightings = []
    g.relationships = []
    g.judgements = []

    client = RecordedFutureClient(api_key)

    for observable in observables:
        result = client.make_observe(observable)
        rules = result['data']['risk'].get('evidenceDetails')
        mapping = Mapping(observable, result)
        if rules:
            if len(rules) > current_app.config['CTR_ENTITIES_LIMIT']:
                rules = rules.sort(
                    key=lambda elem: elem['criticality'],
                    reverse=True
                )[:current_app.config['CTR_ENTITIES_LIMIT']]
            for idx, rule in enumerate(rules):
                indicator = mapping.indicator.extract(idx)
                g.indicators.append(indicator)

                sighting_of_indicator = \
                    mapping.sighting_of_indicator.extract(idx)
                g.sightings.append(sighting_of_indicator) \
                    if sighting_of_indicator else None

                sighting_of_observable = \
                    mapping.sighting_of_observable.extract(idx)
                g.sightings.append(sighting_of_observable) \
                    if sighting_of_observable else None

                judgements = mapping.judgement.extract(idx)
                g.judgements.append(judgements)

                g.relationships.append(
                    mapping.relationship.extract(
                        sighting_of_indicator['id'], indicator['id'],
                        'member-of'
                    )
                )
                g.relationships.append(
                    mapping.relationship.extract(
                        judgements['id'], indicator['id'],
                        'element-of'
                    )
                )

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    observables = filter_observables(get_observables())

    relay_output = []
    for observable in observables:
        if observable['type'] == 'url':
            continue
        types = \
            current_app.config["TYPES_FORMATS"][observable["type"]]
        human_readable_type = types[current_app.config['HUMAN_READABLE']]
        recorded_future_type = types[current_app.config['RECORDED_FUTURE']]
        relay_output.append({
            'id': (
                    f'ref-recorded-future-search-{observable["type"]}-'
                    + observable["value"]
            ),
            'title': (
                f'Search events with this {human_readable_type}'
            ),
            'description': (
                f'Lookup events with this {human_readable_type} '
                'on Recorded Future'
            ),
            'url': current_app.config['REFER_URL'].format(
                type=recorded_future_type,
                value=observable['value']
            ),
            'categories': ['Search', 'Recorded Future'],
        })

    return jsonify_data(relay_output)
