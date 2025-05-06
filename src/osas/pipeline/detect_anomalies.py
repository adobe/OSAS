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

from osas.core import anomaly
from osas.io_utils import config
from osas.core.interfaces import AnomalyDetection, Datasource


class DetectAnomalies():
    ''' class for anomalies detection wrapper methods '''

    def __init__(self, env: str = 'DEV'):
        os.environ["OSAS_ENV"] = env

    def detection_model(self, name: str, load_config: bool = False):
        '''get model specified by name'''
        # get anomaly detection type by name
        dmClass = getattr(sys.modules[anomaly.__name__], name)
        # get label gen obj
        dm = dmClass()
        return dm

    def build_model(self, model: AnomalyDetection, dataset: Datasource) -> dict:
        return model.build_model(dataset)

    def get_scores(self, model: AnomalyDetection, dataset: Datasource) -> [float]:
        return model.__call__(dataset)

    def get_pretrained_model(self, modelName: str, pretrained_data: str) -> AnomalyDetection:
        dmClass = getattr(sys.modules[anomaly.__name__], modelName)
        return dmClass.from_pretrained(pretrained_data)
