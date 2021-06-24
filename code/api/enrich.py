from functools import partial

from flask import Blueprint, g, current_app

from api.client import RecordedFutureClient
from api.mapping import Mapping
from api.schemas import ObservableSchema
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
    observables = get_observables()

    g.indicators = []

    client = RecordedFutureClient(api_key)

    for observable in observables:
        mapping = Mapping(observable)
        result = client.make_observe(observable)
        rules = result['data']['risk'].get('evidenceDetails')
        if rules:
            if len(rules) > current_app.config['CTR_ENTITIES_LIMIT']:
                rules = rules[:current_app.config['CTR_ENTITIES_LIMIT']].sort(
                    key=lambda elem: elem['criticality'], reverse=True)
            for rule in rules:
                indicator = mapping.extract_indicator(result, rule)
                g.indicators.append(indicator)

    return jsonify_result()


@enrich_api.route('/refer/observables', methods=['POST'])
def refer_observables():
    _ = get_jwt()
    _ = get_observables()
    return jsonify_data([])
