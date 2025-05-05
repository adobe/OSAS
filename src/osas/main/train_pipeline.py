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

sys.path.append('')

from src.osas.pipeline import Pipeline
from osas.data.datasources import CSVDataSource, Datasource


def is_numeric(obj):
    attrs = ['__add__', '__sub__', '__mul__', '__truediv__', '__pow__']
    return all(hasattr(obj, attr) for attr in attrs)


def process(params):
    # load and run pipeline
    datasource = CSVDataSource(params.input_file)
    p = Pipeline('DEV')
    p.load_config(params.conf_file)
    if params.incremental:
        p.load_model(params.orig_model_file)
    model = p.build_pipeline(datasource, incremental=params.incremental)
    json.dump(model, open(params.model_file, 'w'), indent=4)


if __name__ == '__main__':
    parser = optparse.OptionParser()
    parser.add_option('--input-file', action='store', dest='input_file', help='location of the input file')
    parser.add_option('--conf-file', action='store', dest='conf_file', help='location of pipeline configuration file')
    parser.add_option('--model-file', action='store', dest='model_file',
                      help='location where to store the pretrained pipeline file')
    parser.add_option('--orig-model-file', action='store', dest='orig_model_file',
                      help='location where to store the pretrained pipeline file')
    parser.add_option('--incremental', action='store_true', help='perform incremental update on the model (will load '
                                                                 '--orig-model-file and save at location specified by '
                                                                 '--model-file)')

    (params, _) = parser.parse_args(sys.argv)

    if params.input_file and params.conf_file and params.model_file:
        if params.incremental and params.orig_model_file:
            process(params)
        else:
            if params.incremental:
                print("Must specify --orig-model-file")
            elif params.orig_model_file:
                print("--orig-model-file must be used with --incremental")
            else:
                process(params)
    else:
        parser.print_help()
