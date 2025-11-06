import requests, json, re
from dateutil import parser
from models import CVE, db
import config
from datetime import datetime

REQUEST_TIMEOUT = 30

def _clean_description(text):
    if not text: return ''
    text = re.sub(r'<[^>]+>', '', text)
    return ' '.join(text.replace('\n',' ').split())

def _parse_scores(metrics):
    v2 = None; v3 = None
    for k in ('cvssMetricV31','cvssMetricV3'):
        if k in metrics and metrics[k]:
            try: v3 = metrics[k][0]['cvssData'].get('baseScore')
            except: pass
    if 'cvssMetricV2' in metrics and metrics['cvssMetricV2']:
        try: v2 = metrics['cvssMetricV2'][0]['cvssData'].get('baseScore')
        except: pass
    return v2, v3

def _parse_dates(obj):
    pub = None; mod = None
    try:
        if obj.get('published'): pub = parser.isoparse(obj.get('published'))
    except: pass
    try:
        if obj.get('lastModified'): mod = parser.isoparse(obj.get('lastModified'))
    except: pass
    return pub, mod

def _extract_cve(item):
    c = item.get('cve') if isinstance(item, dict) and 'cve' in item else item
    cve_id = c.get('id') or c.get('CVE_data_meta',{}).get('ID')
    # identifier: try several possible keys
    identifier = c.get('sourceIdentifier') or c.get('providerMetadata',{}).get('orgId') or c.get('assigner')
    # descriptions
    desc = ''
    for d in c.get('descriptions',[]) or []:
        if d.get('lang') == 'en':
            desc = d.get('value'); break
    if not desc and (c.get('descriptions') or []):
        desc = c.get('descriptions')[0].get('value')
    metrics = c.get('metrics') or {}
    v2, v3 = _parse_scores(metrics)
    pub, mod = _parse_dates(c)
    # status: try common keys in vulnerability wrapper
    status = None
    if isinstance(item, dict):
        status = item.get('vulnStatus') or item.get('vulnerabilityStatus') or item.get('status')
    if not status:
        status = c.get('vulnStatus') or c.get('state') or None
    return {
        'cve_id': cve_id,
        'identifier': identifier,
        'description': _clean_description(desc),
        'base_score_v2': v2,
        'base_score_v3': v3,
        'published_date': pub,
        'last_modified_date': mod,
        'status': status,
        'raw_json': json.dumps(c)
    }

def fetch_page(start_index=0, results_per_page=100, last_mod_start_date=None):
    params = {'startIndex': start_index, 'resultsPerPage': results_per_page}
    if last_mod_start_date: params['lastModStartDate'] = last_mod_start_date
    r = requests.get(config.NVD_API_BASE, params=params, timeout=REQUEST_TIMEOUT)
    r.raise_for_status()
    return r.json()

def sync_page_from_nvd(start_index=0, results_per_page=100):
    data = fetch_page(start_index=start_index, results_per_page=results_per_page)
    vulns = data.get('vulnerabilities') or []
    imported = 0
    for v in vulns:
        item = v if 'cve' in v else v.get('cve', v)
        data_obj = _extract_cve(item)
        if not data_obj['cve_id']: continue
        existing = CVE.query.filter_by(cve_id=data_obj['cve_id']).first()
        if existing:
            existing.description = data_obj['description'] or existing.description
            existing.base_score_v2 = data_obj['base_score_v2'] or existing.base_score_v2
            existing.base_score_v3 = data_obj['base_score_v3'] or existing.base_score_v3
            existing.published_date = data_obj['published_date'] or existing.published_date
            existing.last_modified_date = data_obj['last_modified_date'] or existing.last_modified_date
            existing.status = data_obj['status'] or existing.status
            existing.identifier = data_obj['identifier'] or existing.identifier
            existing.raw_json = data_obj['raw_json']
        else:
            new = CVE(
                cve_id=data_obj['cve_id'],
                identifier=data_obj['identifier'],
                description=data_obj['description'],
                base_score_v2=data_obj['base_score_v2'],
                base_score_v3=data_obj['base_score_v3'],
                published_date=data_obj['published_date'],
                last_modified_date=data_obj['last_modified_date'],
                status=data_obj['status'],
                raw_json=data_obj['raw_json']
            )
            db.session.add(new)
            imported += 1
    db.session.commit()
    return imported

def sync_all_cves(batch_size=200, max_pages=None):
    start = 0; imported = 0; page_no = 0
    while True:
        if max_pages is not None and page_no >= max_pages: break
        res = fetch_page(start_index=start, results_per_page=batch_size)
        vulns = res.get('vulnerabilities') or []
        total_results = res.get('totalResults', None)
        for v in vulns:
            item = v if 'cve' in v else v.get('cve', v)
            data_obj = _extract_cve(item)
            if not data_obj['cve_id']: continue
            existing = CVE.query.filter_by(cve_id=data_obj['cve_id']).first()
            if existing:
                if data_obj['last_modified_date'] and (not existing.last_modified_date or data_obj['last_modified_date'] > existing.last_modified_date):
                    existing.description = data_obj['description'] or existing.description
                    existing.base_score_v2 = data_obj['base_score_v2'] or existing.base_score_v2
                    existing.base_score_v3 = data_obj['base_score_v3'] or existing.base_score_v3
                    existing.published_date = data_obj['published_date'] or existing.published_date
                    existing.last_modified_date = data_obj['last_modified_date'] or existing.last_modified_date
                    existing.status = data_obj['status'] or existing.status
                    existing.identifier = data_obj['identifier'] or existing.identifier
                    existing.raw_json = data_obj['raw_json']
                    db.session.add(existing)
            else:
                new = CVE(
                    cve_id=data_obj['cve_id'],
                    identifier=data_obj['identifier'],
                    description=data_obj['description'],
                    base_score_v2=data_obj['base_score_v2'],
                    base_score_v3=data_obj['base_score_v3'],
                    published_date=data_obj['published_date'],
                    last_modified_date=data_obj['last_modified_date'],
                    status=data_obj['status'],
                    raw_json=data_obj['raw_json']
                )
                db.session.add(new)
                imported += 1
        db.session.commit()
        page_no += 1
        start += batch_size
        if total_results is not None and start >= total_results: break
        if not vulns: break
    return imported

def sync_incremental(last_mod_start_date_iso, batch_size=200):
    start = 0; imported = 0
    while True:
        res = fetch_page(start_index=start, results_per_page=batch_size, last_mod_start_date=last_mod_start_date_iso)
        vulns = res.get('vulnerabilities') or []
        total_results = res.get('totalResults', None)
        for v in vulns:
            item = v if 'cve' in v else v.get('cve', v)
            data_obj = _extract_cve(item)
            if not data_obj['cve_id']: continue
            existing = CVE.query.filter_by(cve_id=data_obj['cve_id']).first()
            if existing:
                existing.description = data_obj['description'] or existing.description
                existing.base_score_v2 = data_obj['base_score_v2'] or existing.base_score_v2
                existing.base_score_v3 = data_obj['base_score_v3'] or existing.base_score_v3
                existing.published_date = data_obj['published_date'] or existing.published_date
                existing.last_modified_date = data_obj['last_modified_date'] or existing.last_modified_date
                existing.status = data_obj['status'] or existing.status
                existing.identifier = data_obj['identifier'] or existing.identifier
                existing.raw_json = data_obj['raw_json']
                db.session.add(existing)
            else:
                new = CVE(
                    cve_id=data_obj['cve_id'],
                    identifier=data_obj['identifier'],
                    description=data_obj['description'],
                    base_score_v2=data_obj['base_score_v2'],
                    base_score_v3=data_obj['base_score_v3'],
                    published_date=data_obj['published_date'],
                    last_modified_date=data_obj['last_modified_date'],
                    status=data_obj['status'],
                    raw_json=data_obj['raw_json']
                )
                db.session.add(new)
                imported += 1
        db.session.commit()
        start += batch_size
        if total_results is not None and start >= total_results: break
        if not vulns: break
    return imported
