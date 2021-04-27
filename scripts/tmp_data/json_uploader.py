import csv
import json
from elasticsearch import helpers, Elasticsearch

es = Elasticsearch([{'host': 'localhost', 'port': 9200}],http_auth=('admin', 'admin'))





data=json.loads(open('result_with_score.json', 'r').read())

helpers.bulk(es, data, index="anomalies", doc_type="type")