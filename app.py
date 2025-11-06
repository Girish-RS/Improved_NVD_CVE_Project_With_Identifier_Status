from flask import Flask, render_template, request, jsonify, abort, redirect, url_for
from models import db, CVE
from utils import sync_page_from_nvd, sync_all_cves, sync_incremental, sync_page_from_nvd as sync_page_helper
from dateutil import parser
from sqlalchemy import or_
from datetime import datetime, timedelta
import config

def create_app():
    app = Flask(__name__, template_folder='templates', static_folder='static')
    app.config.from_object('config')
    db.init_app(app)

    @app.route('/')
    def index():
        return redirect(url_for('list_page'))

    @app.route('/cves/list')
    def list_page():
        return render_template('list.html')

    @app.route('/cves/<string:cve_id>')
    def details_page(cve_id):
        return render_template('details.html', cve_id=cve_id)

    @app.route('/sync', methods=['GET'])
    def sync_page():
        # sync a single page (100) used by UI button
        imported = sync_page_helper(start_index=0, results_per_page=100)
        return jsonify({'imported': imported})

    @app.route('/sync/full', methods=['GET'])
    def sync_full():
        batch_size = request.args.get('batch_size', default=200, type=int)
        max_pages = request.args.get('max_pages', default=None, type=int)
        try:
            imported = sync_all_cves(batch_size=batch_size, max_pages=max_pages)
            return jsonify({'status':'ok', 'imported': imported})
        except Exception as e:
            return jsonify({'status':'error', 'message': str(e)}), 500

    @app.route('/sync/incremental', methods=['GET'])
    def sync_incr():
        since = request.args.get('since')
        batch_size = request.args.get('batch_size', default=200, type=int)
        if not since:
            return jsonify({'error':'missing since param'}), 400
        try:
            parser.isoparse(since)
            imported = sync_incremental(last_mod_start_date_iso=since, batch_size=batch_size)
            return jsonify({'status':'ok', 'imported': imported})
        except Exception as e:
            return jsonify({'status':'error','message':str(e)}), 500

    @app.route('/api/cves')
    def api_list():
        page = request.args.get('page', default=1, type=int)
        per_page = request.args.get('resultsPerPage', default=10, type=int)
        cve_id = request.args.get('cve_id')
        year = request.args.get('year', type=int)
        min_score = request.args.get('min_score', type=float)
        last_modified_days = request.args.get('last_modified_days', type=int)
        sort = request.args.get('sort', default='published_desc')

        q = CVE.query
        if cve_id: q = q.filter(CVE.cve_id.ilike(f"%{cve_id}%"))
        if year:
            start = datetime(year,1,1); end = datetime(year,12,31,23,59,59)
            q = q.filter(CVE.published_date >= start, CVE.published_date <= end)
        if min_score is not None:
            q = q.filter(or_(CVE.base_score_v2 >= min_score, CVE.base_score_v3 >= min_score))
        if last_modified_days is not None:
            cutoff = datetime.utcnow() - timedelta(days=last_modified_days)
            q = q.filter(CVE.last_modified_date >= cutoff)

        if sort == 'published_asc':
            q = q.order_by(CVE.published_date.asc())
        else:
            q = q.order_by(CVE.published_date.desc())

        pagination = q.paginate(page=page, per_page=per_page, error_out=False)
        results = [c.to_dict() for c in pagination.items]
        return jsonify({'total': pagination.total, 'page': pagination.page, 'per_page': pagination.per_page, 'results': results})

    @app.route('/api/cves/<string:cve_id>')
    def api_get(cve_id):
        c = CVE.query.filter_by(cve_id=cve_id).first()
        if not c: abort(404)
        return jsonify(c.to_dict_full())

    return app

if __name__ == '__main__':
    app = create_app()
    with app.app_context():
        db.create_all()
    app.run(debug=True)
