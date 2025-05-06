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

sys.path.append('')

from src.osas.pipeline import Pipeline
from osas.data import datasources
from osas.core.interfaces import Datasource
from osas.io_utils import config


class FetchData(Pipeline):
    ''' class for data fetching '''

    def __init__(self, env: str):
        Pipeline.__init__(self, env)
        os.environ["UBA_ENV"] = env

    def datasource(self, name: str, load_config: str=None) -> Datasource:
        '''datasource generic method'''
        dsClass = getattr(sys.modules[datasources.__name__], name)
        # get args for datasource
        cfg = getattr(sys.modules[config.__name__], name)()
        if load_config:
            cfg.load(load_config)
        ds = dsClass(**(vars(cfg)))  # convert obj to dict to kwargs
        return ds
