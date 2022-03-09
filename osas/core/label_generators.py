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
import pandas as pd
import numpy as np
import re
import math

sys.path.append('')
import json
from osas.core.interfaces import LabelGenerator, Datasource
from osas.core.utils import Tokenizer
from enum import Enum

from lol.api import LOLC
from lol.api import PlatformType

import obfuscation_detection as od


class ObfuscationFieldPlatform(Enum):
    LINUX = od.PlatformType.LINUX
    WINDOWS = od.PlatformType.WINDOWS
    ALL = od.PlatformType.ALL


class ObfuscationField(LabelGenerator):
    """
    This type of Label generator handles fields that contain Linux/Windows commands. It uses machine learning
    to predict if a command is obfuscated or not.
    """

    def __init__(self, field_name: str = '', platform: ObfuscationFieldPlatform = ObfuscationFieldPlatform.ALL,
                 gpu: bool = False):
        if platform == ObfuscationFieldPlatform.LINUX:
            platform = od.PlatformType.LINUX
        elif platform == ObfuscationFieldPlatform.WINDOWS:
            platform = od.PlatformType.WINDOWS
        else:
            platform = od.PlatformType.ALL
        platform_str = str(platform)
        self._model = {
            'field_name': field_name,
            'platform': platform_str,
            'gpu': gpu
        }
        self._classifier = od.ObfuscationClassifier(platform=platform, gpu=gpu)

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        return self._model

    @staticmethod
    def from_pretrained(pretrained: str) -> object:
        lg = ObfuscationField()
        lg._model = json.loads(pretrained)
        platform = od.PlatformType.ALL
        if lg._model['platform'] == 'od.PlatformType.LINUX':
            platform = od.PlatformType.LINUX
        elif lg._model['platform'] == 'od.PlatformType.WINDOWS':
            platform = od.PlatformType.WINDOWS
        lg._classifier = od.ObfuscationClassifier(platform=platform, gpu=bool(lg._model['gpu']))
        return lg

    def __call__(self, object: dict) -> [str]:
        command = object[self._model['field_name']]
        classification = self._classifier([command])[0]
        if classification == 1:
            ret = 'OBFUSCATED'
        else:
            ret = 'NOT OBFUSCATED'
        return [ret]


class LOLFieldPlatform(Enum):
    LINUX = PlatformType.LINUX
    WINDOWS = PlatformType.WINDOWS


class LOLField(LabelGenerator):
    """
    This type of LabelGenerator handles fields that contain Linux/Windows commands. It uses MachineLearning to
    predict if a command is part of a Living of the Land attack
    """

    def __init__(self, field_name: str = '', platform: LOLFieldPlatform = LOLFieldPlatform.LINUX, return_labels=False):
        """
        Constructor
        :param field_name: what field to look for in the data object
        :param platform: chose what model to use Windows/Linux
        :param return_labels: return all generated labels or just the status (BAD, GOOD, NEUTRAL)
        """
        if platform == 'linux':
            platform = PlatformType.LINUX
        elif platform == 'windows':
            platform = PlatformType.WINDOWS
        platform_str = str(platform)
        self._model = {
            'field_name': field_name,
            'platform': platform_str,
            'return_labels': return_labels
        }
        self._classifier = LOLC(platform=platform)

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        return self._model

    @staticmethod
    def from_pretrained(pretrained: str) -> object:
        lg = LOLField()
        lg._model = json.loads(pretrained)
        platform = PlatformType.LINUX
        if lg._model['platform'] == 'PlatformType.WINDOWS':
            platform = PlatformType.WINDOWS
        lg._classifier = LOLC(platform=platform)
        return lg

    def __call__(self, object: dict):
        command = object[self._model['field_name']]
        status, labels = self._classifier(command)
        ret_labels = [status]
        if self._model['return_labels']:
            for label in labels:
                ret_labels.append(label)
        return ret_labels


class NumericField(LabelGenerator):
    """
    This type of LabelGenerator handles numerical fields. It computes the mean and standard deviation and generates
    labels according to the distance between the current value and the mean value
    (value<=sigma NORMAL, sigma<value<=2*sigma BORDERLINE, 2*sigma<value OUTLIER)
    """

    def __init__(self, field_name: str = ''):
        """
        Constructor
        :param field_name: what field to look for in the data object
        """

        self._model = {
            'mean': None,
            'std_dev': None,
            'count': 0,
            'field_name': field_name
        }

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        from osas.data.datasources import CSVDataColumn
        incremental = False
        if self._model['mean'] is not None:
            ex_mean = self._model['mean']
            ex_stdev = self._model['std_dev']
            ex_count = self._model['count']
            incremental = True
        if count_column is None:
            mean = CSVDataColumn(dataset[self._model['field_name']]).mean()
            stdev = CSVDataColumn(dataset[self._model['field_name']]).std()
            count = len(dataset[self._model['field_name']])
            self._model['mean'] = mean
            self._model['std_dev'] = stdev
            self._model['count'] = count
        else:
            mean = CSVDataColumn(dataset[self._model['field_name']] * dataset[count_column]).sum()
            stdev = ((CSVDataColumn(dataset[self._model['field_name']] * dataset[count_column]) - mean) ** 2).sum()
            count = dataset[count_column].sum()
            mean = mean / count
            stdev = math.sqrt(stdev / count)

            self._model['mean'] = mean
            self._model['std_dev'] = stdev
            self._model['count'] = count

        if incremental:
            new_count = ex_count + count
            new_mean = (mean * count + ex_mean * ex_count) / new_count
            new_stdev = math.sqrt(((ex_stdev ** 2) * ex_count + (stdev ** 2) * count) / new_count)
            self._model['mean'] = new_mean
            self._model['std_dev'] = new_stdev
            self._model['count'] = new_count
            
        return self._model

    def __call__(self, input_object: dict) -> [str]:
        labels = []
        mean_val = self._model['mean']
        std_val = self._model['std_dev']
        field_name = self._model['field_name'].upper()
        try:
            cur_value = float(input_object[self._model['field_name']])
        except:
            return ['{0}_BAD_VALUE'.format(field_name)]

        distance = abs((cur_value) - mean_val)

        if distance <= std_val:
            labels.append(field_name + '_NORMAL')
        elif std_val < distance <= (2 * std_val):
            labels.append(field_name + '_BORDERLINE')
        elif (2 * std_val) < distance:
            labels.append(field_name + '_OUTLIER')

        return labels

    @staticmethod
    def from_pretrained(pretrained: str) -> LabelGenerator:
        lg = NumericField()
        lg._model = json.loads(pretrained)
        return lg


class TextField(LabelGenerator):
    """
    This type of LabelGenerator handles text fields. It builds a n-gram based language model and computes the
    perplexity of newly observed data. It also holds statistics over the training data (mean and stdev).
    (perplexity<=sigma NORMAL, sigma<preplexity<=2*sigma BORDERLINE,
    2*perplexity<value OUTLIER)
    """

    def __init__(self, field_name: str, lm_mode='char', ngram_range=(3, 5)):
        """
        Constructor
        :param field_name: What field to look for
        :param lm_mode: Type of LM to build: char or token
        :param ngram_range: N-gram range to use for computation
        """
        self._field_name = field_name
        self._lm_mode = lm_mode
        self._ngram_range = ngram_range
        self._model = {}
        self._total_inf = 0
        self._mean_perplex = 0
        self._std_perplex = 0
        self._accepted_unigrams = {}

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        unigram2count = {}
        for item in dataset:
            text = item[self._field_name]
            unigrams = self._get_ngrams(text, unigrams_only=True)
            occ_number = 1
            if count_column is not None:
                occ_number = item[count_column]
            for unigram in unigrams:
                if unigram not in unigram2count:
                    unigram2count[unigram] = occ_number
                else:
                    unigram2count[unigram] += occ_number
        for unigram in unigram2count:
            if unigram2count[unigram] > 2:
                self._accepted_unigrams[unigram] = 1

        for item in dataset:
            text = item[self._field_name]
            ngrams = self._get_ngrams(text)
            occ_number = 1
            if count_column is not None:
                occ_number = item[count_column]
            for ngram in ngrams:
                if len(ngram) == self._ngram_range[0]:
                    self._total_inf += occ_number
                if ngram in self._model:
                    self._model[ngram] += occ_number
                else:
                    self._model[ngram] = occ_number
        for ngram in self._model:
            self._model[ngram] = math.log(self._model[ngram]) + 1
        ser_model = [self._field_name, self._lm_mode, self._ngram_range[0], self._ngram_range[1], self._mean_perplex,
                     self._std_perplex, self._total_inf]

        all_perplex = np.zeros((len(dataset)), dtype=np.float)
        for ii in range(len(dataset)):
            text = item[self._field_name]
            all_perplex[ii] = self._compute_perplexity(text)

        self._mean_perplex = np.mean(all_perplex)
        self._std_perplex = np.std(all_perplex)
        ser_model[4] = self._mean_perplex
        ser_model[5] = self._std_perplex
        ser_model.append(self._accepted_unigrams)
        for item in self._model:
            ser_model.append(item)
            ser_model.append(self._model[item])

        return ser_model

    def _compute_perplexity(self, text):
        total = 0
        ngrams = self._get_ngrams(text)

        for ngram in ngrams:
            if ngram in self._model:
                sup_count = self._model[ngram]
                total += 1 / sup_count
                # if ngram[:-1] in self._model:
                #     inf_count = self._model[ngram[:-1]]
                # else:
                #     inf_count = self._total_inf
                # total += math.log(sup_count / inf_count)
            else:
                total += -math.log(1e-8)  # small prob for unseen events
        return total / len(ngrams)

    def __call__(self, input_object: dict) -> [str]:
        perplexity = self._compute_perplexity(input_object[self._field_name])
        if perplexity - self._mean_perplex < 2 * self._std_perplex:
            return [perplexity * 10]
        elif perplexity - self._mean_perplex < 4 * self._std_perplex:
            return ['{0}_HIGH_PERPLEXITY'.format(self._field_name.upper()), perplexity * 10]
        else:
            return ['{0}_EXTREEME_PERPLEXITY'.format(self._field_name.upper()), perplexity * 10]

    @staticmethod
    def from_pretrained(pretrained: str) -> LabelGenerator:
        json_obj = json.loads(pretrained)
        field_name = json_obj[0]
        lm_mode = json_obj[1]
        ngram_range = (json_obj[2], json_obj[3])
        new_instance = TextField(field_name, lm_mode, ngram_range)
        new_instance._mean_perplex = json_obj[4]
        new_instance._std_perplex = json_obj[5]
        new_instance._total_inf = json_obj[6]
        new_instance._accepted_unigrams = json_obj[7]
        for ii in range((len(json_obj) - 8) // 2):
            ngram = tuple(json_obj[ii * 2 + 8])
            count = json_obj[ii * 2 + 8 + 1]
            new_instance._model[ngram] = count
        return new_instance

    def _get_ngrams(self, text, unigrams_only=False):
        text = str(text)
        use_chars = self._lm_mode == 'char'
        toks = Tokenizer.tokenize(text, use_chars=use_chars)
        if unigrams_only:
            return toks
        new_toks = []
        for tok in toks:
            if tok in self._accepted_unigrams:
                new_toks.append(tok)
            else:
                new_toks.append('<UNK>')
        toks = new_toks

        # prepend and append
        c_append = self._ngram_range[0] - 1
        start = ['<s>' for _ in range(c_append)]
        stop = ['</s>' for _ in range(c_append)]
        toks = start + toks + stop
        ngrams = []
        for ngram_order in range(self._ngram_range[0], self._ngram_range[1] + 1):
            for ii in range(len(toks) - ngram_order):
                ngram = tuple(toks[ii:ii + ngram_order])
                ngrams.append(ngram)
        return ngrams


class MultinomialField(LabelGenerator):
    def __init__(self, field_name: str = '', absolute_threshold: int = 10, relative_threshold: float = 0.1):
        """
        Constructor
        :param field_name: What field to use
        :param absolute_threshold: Minimum absolute value for occurrences to trigger alert for
        :param relative_threshold: Minimum relative value for occurrences to trigger alert for
        """
        self._mfc = MultinomialFieldCombiner([field_name], absolute_threshold, relative_threshold)

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        return self._mfc.build_model(dataset, count_column)

    def __call__(self, item: dict) -> [str]:
        lbls = self._mfc(item)
        lbls = [l.replace('_PAIR', '') for l in lbls]
        return lbls

    @staticmethod
    def from_pretrained(pretrained: str) -> LabelGenerator:
        lg = MultinomialFieldCombiner()
        lg._model = json.loads(pretrained)
        mf = MultinomialField()
        mf._mfc = lg
        return mf


class MultinomialFieldCombiner(LabelGenerator):
    def __init__(self, field_names: [str] = [], absolute_threshold: int = 10, relative_threshold: float = 0.1):
        """
        Constructor
        :param field_names: What fields to combine
        :param absolute_threshold: Minimum absolute value for occurrences to trigger alert for
        :param relative_threshold: Minimum relative value for occurrences to trigger alert for
        """

        self._model = {'pair2count': {},
                       'pair2prob': {},
                       'absolute_threshold': absolute_threshold,
                       'relative_threshold': relative_threshold,
                       'field_names': field_names
                       }

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        pair2count = self._model['pair2count']  # this is used for incremental updates
        total = 0
        for item in dataset:
            combined = [str(item[field]) for field in self._model['field_names']]
            combined = '(' + ','.join(combined) + ')'
            occ_number = 1
            if count_column is not None:
                occ_number = item[count_column]
            total += occ_number
            if combined not in pair2count:
                pair2count[combined] = occ_number
            else:
                pair2count[combined] += occ_number
        pair2prob = {}
        for key in pair2count:
            pair2prob[key] = pair2count[key] / total

        self._model['pair2count'] = pair2count
        self._model['pair2prob'] = pair2prob

        return self._model

    def __call__(self, item: dict) -> [str]:
        fname = ('_'.join(self._model['field_names'])).upper() + '_PAIR'
        combined = [str(item[field]) for field in self._model['field_names']]
        combined = '(' + ','.join(combined) + ')'
        if combined not in self._model['pair2count']:
            return ['UNSEEN_' + fname]
        else:
            labels = []

            prob = self._model['pair2prob'][combined]
            cnt = self._model['pair2count'][combined]

            if cnt < self._model['absolute_threshold']:
                labels.append('LOW_OBS_COUNT_FOR_' + fname)
            if prob < self._model['relative_threshold']:
                labels.append('LOW_OBS_PROB_FOR_' + fname)
        return labels

    @staticmethod
    def from_pretrained(pretrained: str) -> LabelGenerator:
        lg = MultinomialFieldCombiner()
        lg._model = json.loads(pretrained)
        return lg


class NumericalFieldCombiner(LabelGenerator):
    def __init__(self, field_names: [str], normalize=True):
        """

        :param field_names: What fields to combine
        :param normalize: Normalize each field using standard deviation before processing
        """
        self._field_names = field_names
        self._normalize = normalize

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        pass

    def __call__(self, input_object: dict) -> [str]:
        pass

    @staticmethod
    def from_pretrained(pretrained: str) -> LabelGenerator:
        pass


class KeywordBased(LabelGenerator):
    def __init__(self, keyword_list: list, field_name: str):
        if isinstance(keyword_list, str):
            keyword_list = re.sub('[^0-9a-zA-Z]+', ' ', keyword_list)
            keyword_list = keyword_list.split(' ')
        self._label_list = [item for item in keyword_list]
        self._field_name = field_name

    def __call__(self, input_object: dict):
        label_list = []
        text = str(input_object[self._field_name])
        text = re.sub('[^0-9a-zA-Z]+', ' ', text)
        word_list = text.split(' ')
        for ii in range(len(self._label_list)):
            if self._label_list[ii] in word_list:
                label_list.append("{0}_KEYWORD_{1}".format(self._field_name.upper(), self._label_list[ii].upper()))
        return label_list

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        return {'field_name': self._field_name,
                'keyword_list': self._label_list}

    @staticmethod
    def from_pretrained(pretrained: str) -> object:
        obj = json.loads(pretrained)
        keyword_list = obj['keyword_list']
        field_name = obj['field_name']
        klg = KeywordBased(keyword_list, field_name)
        return klg


class KnowledgeBased(LabelGenerator):
    def __init__(self, rules_and_labels_tuple_list: list, field_name: str):
        if isinstance(rules_and_labels_tuple_list, str):
            # we need to parse this
            rules_and_labels_tuple_list = eval(rules_and_labels_tuple_list)
        self._regex_list = [re.compile(item[0]) for item in rules_and_labels_tuple_list]
        self._regex_list_str = [item[0] for item in rules_and_labels_tuple_list]
        self._label_list = [item[1] for item in rules_and_labels_tuple_list]
        self._field_name = field_name

    def __call__(self, input_object: dict) -> [str]:
        label_list = []
        text = str(input_object[self._field_name])
        for ii in range(len(self._label_list)):
            if self._regex_list[ii].search(text):
                label_list.append(self._label_list[ii])
        return label_list

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        return {
            'field_name': self._field_name,
            'label_list': self._label_list,
            'regex_list': self._regex_list_str
        }

    @staticmethod
    def from_pretrained(pretrained: str) -> object:
        obj = json.loads(pretrained)
        label_list = obj['label_list']
        regex_list = obj['regex_list']
        field_name = obj['field_name']
        reg_lab = [(regex, label) for regex, label in zip(regex_list, label_list)]
        kblg = KnowledgeBased(reg_lab, field_name)
        return kblg


if __name__ == '__main__':
    mfc = MultinomialFieldCombiner(['user', 'parent_process'], absolute_threshold=500, relative_threshold=0.005)
    nfc = NumericField('count')
    tf = TextField('command', lm_mode='token', ngram_range=(3, 5))
    klg = KeywordBased(keyword_list=['bash', 'java', 'netcat', 'sudo', 'apache2'], field_name='command')
    from osas.data.datasources import CSVDataSource

    dataset = CSVDataSource('corpus/test.csv')
    print("Building model")
    klg.build_model(dataset)
    print("Done")

    #    rez = mfc.build_model(dataset)
    for item in dataset[:20]:
        print("\n\n")
        print(item)
        print("")
        print(klg(item))
        print("\n\n")
        print("=" * 20)
