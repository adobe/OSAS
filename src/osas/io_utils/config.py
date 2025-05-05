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

import sys
import ast
from builtins import object, super
import collections
import configparser
import pandas as pd
from dataclasses import dataclass, field


@dataclass
class Config(object):
    '''Generic base class to load/save config'''

    def _eval_str(self, s):
        '''convert type to actual type'''
        try:
            return ast.literal_eval(s)
        except:
            return s

    def save(self, filename):
        """Save configuration to file."""
        self.__config__ = self.__class__.__name__
        sorted_dict = collections.OrderedDict(sorted(self.__dict__.items()))
        # sort dictionary
        config = configparser.ConfigParser()
        config.add_section(self.__config__)  # write header
        for k, v in sorted_dict.items():  # for python3 use .items()
            if not k.startswith("_"):  # write only non-private properties
                if isinstance(v, float):  # if we are dealing with a float
                    str_v = str(v)
                    if "e" not in str_v and "." not in str_v:
                        # stopconfusion with an int by appending a ".0"
                        v = str_v + ".0"
                v = str(v)
                config.set(self.__config__, k, v)
        with fopen(filename, 'w') as cfgfile:
            config.write(cfgfile)

    def load(self, filename):
        '''Load configuration from file'''
        __config__ = self.__class__.__name__
        config = configparser.ConfigParser()
        config.read(filename)
        # check to see if the config file has the appropriate section
        if not config.has_section(__config__):
            sys.stderr.write("ERROR: File:{} is not a valid configuration file"
                             " for the selected task: Missing section:[{}]\n"
                             .format(filename, __config__))
            sys.exit(1)
        for k, v in config.items(__config__):
            self.__dict__[k] = self._eval_str(v)


# ****Beware****
# Don't save secrets as default config
# Use local config file (not git synced) to save secrets


# ML data dataclasses
@dataclass
class CSVDataSource(Config):
    filename: str = field(default='corpus/test.csv')


@dataclass
class CSVDataColumn(Config):
    data: pd.DataFrame = field(default=pd.DataFrame())


# Label Generator dataclasses
@dataclass
class ObfuscationField(Config):
    field_name: str = field(default='command')
    gpu: bool = field(default=False)


@dataclass
class NumericField(Config):
    field_name: str = field(default='count')
    group_by: str = field(default=None)
    mode: str = field(default='stdev')
    borderline_threshold: float = field(default=1)
    outlier_threshold: float = field(default=2)
    label_for_normal: bool = field(default=True)


@dataclass
class TextField(Config):
    field_name: str = field(default='command')
    lm_mode: str = field(default='char')
    ngram_range: tuple = field(default=(3, 5))


@dataclass
class MultinomialField(Config):
    field_name: str = field(default='user')
    absolute_threshold: int = field(default=10)
    relative_threshold: float = field(default=0.1)
    group_by: str = field(default=None)


@dataclass
class LOLField(Config):
    field_name: str = field(default='command')
    platform: str = field(default='linux')


@dataclass
class NumericalFieldCombiner(Config):
    field_names: list = field(default_factory=lambda: [])
    normalize: bool = field(default=True)


@dataclass
class MultinomialFieldCombiner(Config):
    field_names: list = field(default_factory=lambda: [])
    absolute_threshold: float = field(default=500)
    relative_threshold: float = field(default=0.005)
    group_by: str = field(default=None)


@dataclass
class KeywordBased(Config):
    keyword_list: list = field(default_factory=lambda: [])
    field_name: str = field(default='count')


@dataclass
class KnowledgeBased(Config):
    rules_and_labels_tuple_list: list = field(default_factory=lambda: [()])
    field_name: str = field(default='')

# mfc = MultinomialFieldCombiner()
# mfc.load('osas/etc/ad_config.conf')
# print(vars(mfc))
