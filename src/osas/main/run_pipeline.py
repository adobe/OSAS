#
# Authors: Security Intelligence Team within the Security Coordination Center
#
# Copyright (c) 2018 Adobe Systems Incorporated. All rights reserved.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
# http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

import optparse
import sys
import json
from elasticsearch import helpers, Elasticsearch

sys.path.append('')

from src.osas.pipeline import Pipeline
from osas.data.datasources import CSVDataSource, Datasource
import numpy as np


def is_numeric(obj):
    attrs = ['__add__', '__sub__', '__mul__', '__truediv__', '__pow__']
    return all(hasattr(obj, attr) for attr in attrs)


def process(params):
    # load and run pipeline
    datasource = CSVDataSource(params.input_file)
    p = Pipeline('DEV')
    p.load_config(params.conf_file)
    p.load_model(params.model_file)
    p(datasource)
    # save, if necessary
    if params.output_file:
        datasource.save(open(params.output_file, 'w'))
    # push to elasticsearch
    if not params.no_elastic:
        try:
            es = Elasticsearch([{'host': 'localhost', 'port': 9200}], http_auth=('admin', 'admin'))
            data = [item for item in datasource]
            for item in data:
                item['model'] = p._scoring_model_name
                item['raw'] = str(item['labels'])
                for key in item:
                    if item[key] == 'NaN' or (is_numeric(item[key]) and np.isnan(item[key])):
                        item[key] = None
            helpers.bulk(es, data, index="anomalies", doc_type="type")
        except Exception as e:
            sys.stdout.write('Unable to push data to ElasticSearch:  {0}\n'.format(str(e)))


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('--input-file', action='store', dest='input_file', help='location of the input file')
    parser.add_option('--conf-file', action='store', dest='conf_file', help='location of pipeline configuration file')
    parser.add_option('--model-file', action='store', dest='model_file', help='location of pretrained pipeline file')
    parser.add_option('--output-file', action='store', dest='output_file', help='output-file (optional)')
    parser.add_option('--no-elastic', action='store_true', dest='no_elastic', help='don\'t push data to Elastic')
    (params, _) = parser.parse_args(sys.argv)

    if params.input_file and params.conf_file and params.model_file:
        if params.no_elastic and not params.output_file:
            sys.stdout.write("This run will not produce any results. You need to either specify --output-file or "
                             "remove --no-elastic\n")
        else:
            process(params)
    else:
        parser.print_help()
