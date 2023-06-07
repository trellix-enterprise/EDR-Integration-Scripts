import json


def action_history_legacy(logger, res, itemsPerPage):

    items = []

    for idx, item in enumerate(res['data']):
        items.append(item['attributes'])
        items[idx]['id'] = item['id']
        items[idx]['caseId'] = items[idx]['investigationId']
        del items[idx]['investigationId']

    response_data = {
        'currentItemCount': len(res['data']),
        'items': items,
        'itemsPerPage': itemsPerPage,
        'startIndex': 0,
        'totalItems': res['meta']['totalResourceCount']
    }

    logger.info(json.dumps(response_data))
