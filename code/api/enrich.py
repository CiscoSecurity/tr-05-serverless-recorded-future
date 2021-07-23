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
    api_key = get_jwt()
    observables = filter_observables(get_observables())

    g.verdicts = []

    client = RecordedFutureClient(api_key)

    for observable in observables:
        result = client.make_observe(observable)
        mapping = Mapping(observable, result)

        if result['data']['risk']['evidenceDetails']:
            g.verdicts.append(mapping.verdict.extract())

    return jsonify_result()


@enrich_api.route('/observe/observables', methods=['POST'])
def observe_observables():
    api_key = get_jwt()
    observables = filter_observables(get_observables())

    g.indicators = []
    g.sightings = []
    g.relationships = []
    g.judgements = []
    g.verdicts = []

    client = RecordedFutureClient(api_key)

    for observable in observables:
        result = client.make_observe(observable)
        if not result:
            continue
        rules = result['data']['risk'].get('evidenceDetails')
        mapping = Mapping(observable, result)

        judgements_for_observable = []

        limit = current_app.config['CTR_ENTITIES_LIMIT']

        if rules:
            rules.sort(
                key=lambda elem: elem['criticality'],
                reverse=True
            )
            rules = rules[:limit]
            for rule in rules:
                indicator = mapping.indicator.extract(rule)
                g.indicators.append(indicator)

                sighting_of_indicator = \
                    mapping.sighting_of_indicator.extract(rule)
                g.sightings.append(sighting_of_indicator) \
                    if sighting_of_indicator else None

                judgement = mapping.judgement.extract(rule)
                judgements_for_observable.append(judgement)

                g.relationships.append(
                    mapping.relationship.extract(
                        sighting_of_indicator['id'], indicator['id'],
                        'member-of'
                    )
                )
                g.relationships.append(
                    mapping.relationship.extract(
                        judgement['id'], indicator['id'],
                        'element-of'
                    )
                )
            sightings = result['data']['sightings'][:limit]
            for sighting in sightings:
                if len(g.sightings) < limit:
                    sighting_of_observable = \
                        mapping.sighting_of_observable.extract(sighting)
                    g.sightings.append(sighting_of_observable) \
                        if sighting_of_observable else None

        if judgements_for_observable:
            g.judgements.extend(judgements_for_observable)
            verdict = mapping.verdict.extract()
            verdict['judgement_id'] = judgements_for_observable[0].get('id')
            g.verdicts.append(verdict)

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
