#
# Authors: Security Intelligence Team within the Security Coordination Center
#
# Copyright (c) 2022 Adobe Systems Incorporated. All rights reserved.
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
import re
import sys

import tqdm
from elasticsearch import helpers, Elasticsearch

sys.path.append('')

from osas.data.datasources import CSVDataSource, Datasource
import yaml
import os


def is_numeric(obj):
    attrs = ['__add__', '__sub__', '__mul__', '__truediv__', '__pow__']
    return all(hasattr(obj, attr) for attr in attrs)


def _get_all_yaml_files(root: str):
    all_files = []
    for path, subdirs, files in os.walk(root):
        for name in files:
            if name.endswith('.yaml'):
                all_files.append(os.path.join(path, name))
    return all_files


def _load_rules(rules_folder: str) -> dict:
    all_rule_files = _get_all_yaml_files(rules_folder)
    all_rules = []
    for file in all_rule_files:
        with open(file, 'r') as f:
            rules_pack = yaml.safe_load(f)
            if rules_pack is None:
                continue
            if 'rule name' not in rules_pack:
                sys.stdout.write('Invalid rule file {0}. Missing rule name\n'.format(file))
                sys.exit(0)
            if 'rule label' not in rules_pack:
                sys.stdout.write('Invalid rule file {0}. Missing rule label\n'.format(file))
                sys.exit(0)
            if 'rule score' not in rules_pack:
                sys.stdout.write('Invalid rule file {0}. Missing rule score\n'.format(file))
                sys.exit(0)
            all_rules.append(rules_pack)
    return all_rules


def _apply_rules(datasource: Datasource, rules: dict):
    scores = datasource['score']
    labels = datasource['labels']
    index = 0
    regex_cache = {}
    for item in tqdm.tqdm(datasource):
        for rule in rules:
            rule_name = rule['rule name']
            rule_score = float(rule['rule score'])
            rule_label = rule['rule label']
            cases = rule['conditions']
            for case in cases:
                valid = True
                for attribute_name in cases[case]:
                    attribute_values = cases[case][attribute_name]
                    if not isinstance(attribute_values, list):
                        attribute_values = [attribute_values]
                    if attribute_name not in item:
                        sys.stdout.write('Your dataset does not contain "{0}"\n'.format(attribute_name))
                        sys.exit(0)
                    found = False
                    for attribute_value in attribute_values:
                        if attribute_value not in regex_cache:
                            regex_cache[attribute_value] = re.compile(attribute_value)
                        compiled_regex=regex_cache[attribute_value]
                        if compiled_regex.match(item[attribute_name]):
                            found = True
                            break
                    if not found:
                        valid = False
                        break
                if valid:
                    scores[index] += rule_score
                    if len(labels[index]) > 3:
                        labels[index] = labels[index][:-1] + ', \'' + rule_label + '\']'
                    else:
                        labels[index] = '[\'{0}\']'.format(rule_label)
        index += 1

    datasource['_labels'] = labels


def process(params):
    # load and run pipeline
    rules_pack = _load_rules(params.rules_folder)
    datasource = CSVDataSource(params.input_file)
    _apply_rules(datasource, rules_pack)

    # save, if necessary
    if params.output_file:
        datasource.save(open(params.output_file, 'w'))
    # push to elasticsearch
    if not params.no_elastic:
        try:
            es = Elasticsearch([{'host': 'localhost', 'port': 9200}], http_auth=('admin', 'admin'))
            data = [item for item in datasource]
            helpers.bulk(es, data, index="anomalies", doc_type="type")
        except Exception as e:
            sys.stdout.write('Unable to push data to ElasticSearch:  {0}\n'.format(str(e)))


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('--input-file', action='store', dest='input_file', help='location of the input file')
    parser.add_option('--rules-folder', action='store', dest='rules_folder', help='location of rules')
    parser.add_option('--output-file', action='store', dest='output_file', help='output-file (optional)')
    parser.add_option('--no-elastic', action='store_true', dest='no_elastic', help='don\'t push data to Elastic')
    (params, _) = parser.parse_args(sys.argv)

    if params.input_file and params.rules_folder:
        if params.no_elastic and not params.output_file:
            sys.stdout.write("This run will not produce any results. You need to either specify --output-file or "
                             "remove --no-elastic\n")
        else:
            process(params)
    else:
        parser.print_help()
