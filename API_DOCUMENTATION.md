# API Documentation

## Frontend
- GET /cves/list
- GET /cves/<cve_id>

## Sync
- GET /sync  (sync a single page used by UI)
- GET /sync/full?batch_size=200&max_pages=3
- GET /sync/incremental?since=2025-10-01T00:00:00Z

## API
- GET /api/cves?page=1&resultsPerPage=10
- GET /api/cves/<cve_id>
