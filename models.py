from flask_sqlalchemy import SQLAlchemy
import json
db = SQLAlchemy()

class CVE(db.Model):
    __tablename__ = 'cves'
    id = db.Column(db.Integer, primary_key=True)
    cve_id = db.Column(db.String(80), unique=True, nullable=False, index=True)
    identifier = db.Column(db.String(200), nullable=True)
    description = db.Column(db.Text)
    base_score_v2 = db.Column(db.Float, nullable=True)
    base_score_v3 = db.Column(db.Float, nullable=True)
    published_date = db.Column(db.DateTime)
    last_modified_date = db.Column(db.DateTime)
    status = db.Column(db.String(80), nullable=True)
    raw_json = db.Column(db.Text)

    def to_dict(self):
        return {
            'cve_id': self.cve_id,
            'identifier': self.identifier,
            'description': (self.description[:200] + '...') if self.description and len(self.description)>200 else self.description,
            'base_score_v2': self.base_score_v2,
            'base_score_v3': self.base_score_v3,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'status': self.status
        }

    def to_dict_full(self):
        return {
            'cve_id': self.cve_id,
            'identifier': self.identifier,
            'description': self.description,
            'base_score_v2': self.base_score_v2,
            'base_score_v3': self.base_score_v3,
            'published_date': self.published_date.isoformat() if self.published_date else None,
            'last_modified_date': self.last_modified_date.isoformat() if self.last_modified_date else None,
            'status': self.status,
            'raw_json': json.loads(self.raw_json) if self.raw_json else None
        }
