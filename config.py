import os
BASE_DIR = os.path.abspath(os.path.dirname(__file__))
SQLALCHEMY_DATABASE_URI = os.environ.get('DATABASE_URL') or 'sqlite:///' + os.path.join(BASE_DIR, 'cves.db')
SQLALCHEMY_TRACK_MODIFICATIONS = False
NVD_API_BASE = 'https://services.nvd.nist.gov/rest/json/cves/2.0'
