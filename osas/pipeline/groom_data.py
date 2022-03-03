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

import os
import sys
import json

sys.path.append('')

# from osas.pipeline.pipeline import Pipeline
from osas.core import label_generators
from osas.io_utils import config
from osas.core.interfaces import LabelGenerator, Datasource
import configparser


class GroomData():
    ''' class for data grooming wrapper methods '''

    def __init__(self, env: str = 'DEV'):
        # Pipeline.__init__(self, env)
        os.environ["OSAS_ENV"] = env

    def label_generator(self, name: str,
                        load_config: str = None) -> LabelGenerator:
        '''generate label specified by name'''
        # get label generator class from name
        lgClass = getattr(sys.modules[label_generators.__name__], name)
        # get args for the label generator
        cfg = getattr(sys.modules[config.__name__], name)()
        if load_config:
            if isinstance(load_config, configparser.SectionProxy):
                cfg = load_config
            else:
                cfg.load(load_config)
        # get label gen obj
        # di = {key: eval(cfg[key]) for key in cfg}
        di = {}
        for key in cfg:
            try:
                val = eval(cfg[key])
            except:
                val = cfg[key]
            di[key] = val
        del di['generator_type']
        lg = lgClass(**di)  # convert obj to dict to kwargs
        return lg

    def from_pretrained(self, name: str,
                        pretrained: dict) -> LabelGenerator:
        '''generate label specified by name'''
        # get label generator class from name
        lgClass = getattr(sys.modules[label_generators.__name__], name)
        # get args for the label generator
        cfg = getattr(sys.modules[config.__name__], name)()
        return lgClass.from_pretrained(json.dumps(pretrained))
        # if load_config:
        #     if isinstance(load_config, configparser.SectionProxy):
        #         cfg = load_config
        #     else:
        #         cfg.load(load_config)
        # # get label gen obj
        # # di = {key: eval(cfg[key]) for key in cfg}
        # di = {}
        # for key in cfg:
        #     try:
        #         val = eval(cfg[key])
        #     except:
        #         val = cfg[key]
        #     di[key] = val
        # del di['generator_type']
        # lg = lgClass(**di)  # convert obj to dict to kwargs
        # return lg

    def build_model(self, model: LabelGenerator,
                    dataset: Datasource, count_column: str) -> dict:
        return model.build_model(dataset, count_column)

    def get_labels(self, model: LabelGenerator,
                   input_object: dict) -> [str]:
        return model.__call__(input_object)

    def get_pretrained_model(self, modelName: str,
                             pretrained_data: str) -> LabelGenerator:
        lgClass = getattr(sys.modules[label_generators.__name__],
                          modelName)
        return lgClass.from_pretrained(pretrained_data)
