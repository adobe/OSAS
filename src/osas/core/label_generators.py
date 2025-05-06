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

from cProfile import label
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

    def __init__(self,
                 field_name: str = '',
                 group_by: str = None,
                 stdev: bool = True,
                 stdev_borderline_threshold: float = 1,
                 stdev_outlier_threshold: float = 2,
                 spike: str = 'none',
                 spike_inverse: bool = False,
                 spike_borderline_threshold: float = 10,
                 spike_outlier_threshold: float = 20,
                 label_for_normal: bool = True):
        """
        Constructor
        :param field_name: what field to look for in the data object
        """

        if spike not in ('none', 'ratio', 'fixed'):
            print("Unknown spike {0} for NumericField. Expected 'none', 'ratio', or 'fixed'")

        if not stdev and spike == 'none':
            print("stdev or spike must be activated for NumericField to operate")

        self._model = {
            'mean': None,
            'std_dev': None,
            'count': 0,
            'field_name': field_name,
            'group_by': group_by,
            'stdev': stdev,
            'stdev_borderline_threshold': stdev_borderline_threshold,
            'stdev_outlier_threshold': stdev_outlier_threshold,
            'spike': spike,
            'spike_inverse': spike_inverse,
            'spike_borderline_threshold': spike_borderline_threshold,
            'spike_outlier_threshold': spike_outlier_threshold,
            'label_for_normal': label_for_normal
        }

    def _get_group_by_value(self, item, group_by):
        if isinstance(group_by, str):
            return str(item[group_by])
        else:
            return "({0})".format(','.join([str(item[k]) for k in group_by]))

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        incremental = False
        if self._model['mean'] is not None:
            ex_mean = self._model['mean']
            ex_stdev = self._model['std_dev']
            ex_count = self._model['count']
            incremental = True
        group_by = self._model['group_by']
        if group_by is None:
            mean = 0
            stdev = 0
            count = 0
        else:
            mean = {}
            stdev = {}
            count = {}
        # mean
        for item in dataset:
            cc = 1
            if count_column is not None:
                cc = int(item[count_column])
            if group_by is None:
                mean += item[self._model['field_name']] * cc
                count += cc
            else:
                key = self._get_group_by_value(item, group_by)
                if key not in mean:
                    mean[key] = 0
                    stdev[key] = 0
                    count[key] = 0
                mean[key] += item[self._model['field_name']] * cc
                count[key] += cc

        if group_by is None:
            mean /= count
        else:
            for key in mean:
                mean[key] /= count[key]
        # stdev
        for item in dataset:
            cc = 1
            if count_column is not None:
                cc = int(item[count_column])
            if group_by is None:
                stdev += ((item[self._model['field_name']] - mean) ** 2) * cc
            else:
                key = self._get_group_by_value(item, group_by)
                stdev[key] += ((item[self._model['field_name']] - mean[key]) ** 2) * cc

        if group_by is None:
            stdev /= count
            stdev = math.sqrt(stdev)
        else:
            for key in stdev:
                stdev[key] /= count[key]
                stdev[key] = math.sqrt(stdev[key])

        # update if incremental
        if incremental:
            if group_by is None:
                new_mean = (ex_mean * ex_count + mean * count) / (ex_count + count)
                new_stdev = (((ex_stdev ** 2) * ex_count) + ((stdev ** 2) * count)) / (ex_count + count)
                new_count = ex_count + count
            else:
                new_mean = {}
                new_stdev = {}
                new_count = {}
                for key in mean:
                    if key in ex_mean:
                        new_mean[key] = (ex_mean[key] * ex_count[key] + mean[key] * count[key]) / (
                                ex_count[key] + count[key])
                        new_stdev[key] = (((ex_stdev[key] ** 2) * ex_count[key]) + ((stdev[key] ** 2) * count[key])) / (
                                ex_count[key] + count[key])
                        new_count[key] = ex_count[key] + count[key]
                    else:
                        new_mean[key] = mean[key]
                        new_stdev[key] = stdev[key]
                        new_count[key] = count[key]
                # transfer ex-values
                for key in ex_mean:
                    if key not in mean:
                        new_mean[key] = ex_mean[key]
                        new_stdev[key] = ex_stdev[key]
                        new_count[key] = ex_count[key]

            mean = new_mean
            stdev = new_stdev
            count = new_count
        # store
        self._model['mean'] = mean
        self._model['std_dev'] = stdev
        self._model['count'] = count
        # check sanity and warn user
        font_style = '\033[93m'
        mean_is_zero = False
        stdev_is_zero = False
        if self._model['group_by'] is None:
            if self._model['mean'] == 0:
                mean_is_zero = True
            if self._model['std_dev'] == 0:
                stdev_is_zero = True
        else:
            for key in self._model['mean']:
                if self._model['mean'][key] == 0:
                    mean_is_zero = True
                if self._model['std_dev'][key] == 0:
                    stdev_is_zero = True
        if mean_is_zero and self._model['stdev'] == False:
            sys.stdout.write('\t{0}::WARNING:You have a mean of 0. Any deviation will be flagged\n'.format(font_style))
        if stdev_is_zero and self._model['stdev'] == True:
            sys.stdout.write(
                '\t{0}::WARNING:You have a standard deviation of 0. Any deviation will be flagged\n'.format(font_style))

        return self._model

    # def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
    #     from osas.data.datasources import CSVDataColumn
    #     incremental = False
    #     if self._model['mean'] is not None:
    #         ex_mean = self._model['mean']
    #         ex_stdev = self._model['std_dev']
    #         ex_count = self._model['count']
    #         incremental = True
    #     if count_column is None:
    #         mean = CSVDataColumn(dataset[self._model['field_name']]).mean()
    #         stdev = CSVDataColumn(dataset[self._model['field_name']]).std()
    #         count = len(dataset[self._model['field_name']])
    #         self._model['mean'] = mean
    #         self._model['std_dev'] = stdev
    #         self._model['count'] = count
    #     else:
    #         mean = CSVDataColumn(dataset[self._model['field_name']] * dataset[count_column]).sum()
    #         stdev = ((CSVDataColumn(dataset[self._model['field_name']] * dataset[count_column]) - mean) ** 2).sum()
    #         count = dataset[count_column].sum()
    #         mean = mean / count
    #         stdev = math.sqrt(stdev / count)
    #
    #         self._model['mean'] = mean
    #         self._model['std_dev'] = stdev
    #         self._model['count'] = count
    #
    #     if incremental:
    #         new_count = ex_count + count
    #         new_mean = (mean * count + ex_mean * ex_count) / new_count
    #         new_stdev = math.sqrt(((ex_stdev ** 2) * ex_count + (stdev ** 2) * count) / new_count)
    #         self._model['mean'] = new_mean
    #         self._model['std_dev'] = new_stdev
    #         self._model['count'] = new_count
    #
    #     return self._model

    def _get_labels(self, cur_value, mean_val, std_val, stdev, stdev_borderline_threshold,
                    stdev_outlier_threshold, spike, spike_inverse, spike_borderline_threshold,
                    spike_outlier_threshold, label_for_normal):
        labels = []
        if stdev:
            if std_val == 0:
                std_val = 0.01
            stdev_ratio = abs(cur_value - mean_val) / std_val

        # if using both stdev and spike, calculate a spike from the stdev
        if stdev and spike != 'none':
            if not spike_inverse:
                mean_val = mean_val + std_val
            else:
                mean_val = mean_val - std_val

        if spike == 'ratio':
            if not spike_inverse:
                if mean_val == 0:
                    mean_val = 0.01
                spike_ratio = cur_value / mean_val
            else:
                if cur_value == 0:
                    cur_value = 0.01
                spike_ratio = mean_val / cur_value
        elif spike == 'fixed':
            if not spike_inverse:
                spike_ratio = cur_value - mean_val
            else:
                spike_ratio = mean_val - cur_value

        field_name = self._model['field_name'].upper()

        if stdev and spike != 'none' and stdev_ratio < stdev_outlier_threshold:
            # if both are activated, and event is within stdev outlier threshold
            if label_for_normal:
                labels.append('{0}_NORMAL'.format(field_name))
        else:
            if stdev and spike == 'none':
                # only stdev is activated
                ratio = stdev_ratio
                borderline_threshold = stdev_borderline_threshold
                outlier_threshold = stdev_outlier_threshold
            else:
                # if only spike is activated or both are activated, use spike ratio
                ratio = spike_ratio
                borderline_threshold = spike_borderline_threshold
                outlier_threshold = spike_outlier_threshold

            if label_for_normal and ratio < borderline_threshold:
                labels.append('{0}_NORMAL'.format(field_name))
            elif borderline_threshold < ratio < outlier_threshold:
                labels.append('{0}_BORDERLINE'.format(field_name))
            elif ratio >= outlier_threshold:
                labels.append('{0}_OUTLIER'.format(field_name))

        return labels

    def __call__(self, input_object: dict) -> [str]:
        labels = []
        mean_val = self._model['mean']
        std_val = self._model['std_dev']
        count_val = self._model['count']
        field_name = self._model['field_name'].upper()
        label_for_normal = True
        if 'label_for_normal' in self._model:
            label_for_normal = self._model['label_for_normal']

        stdev = True
        if 'stdev' in self._model:
           stdev = bool(self._model['stdev'])

        stdev_borderline_threshold = 1
        if 'stdev_borderline_threshold' in self._model:
            stdev_borderline_threshold = self._model['stdev_borderline_threshold']

        stdev_outlier_threshold = 2
        if 'stdev_outlier_threshold' in self._model:
            stdev_outlier_threshold = self._model['stdev_outlier_threshold']

        spike = 'none'
        if 'spike' in self._model:
            spike = self._model['spike']

        spike_inverse = False
        if 'spike_inverse' in self._model:
           spike_inverse = bool(self._model['spike_inverse'])

        spike_borderline_threshold = 10
        if 'spike_borderline_threshold' in self._model:
            spike_borderline_threshold = self._model['spike_borderline_threshold']

        spike_outlier_threshold = 20
        if 'spike_outlier_threshold' in self._model:
            spike_outlier_threshold = self._model['spike_outlier_threshold']

        try:
            cur_value = float(input_object[self._model['field_name']])
        except:
            return ['{0}_BAD_VALUE'.format(field_name)]
        group_by = self._model['group_by']
        if group_by is None:
            new_labels = self._get_labels(cur_value,
                                          mean_val,
                                          std_val,
                                          stdev,
                                          stdev_borderline_threshold,
                                          stdev_outlier_threshold,
                                          spike,
                                          spike_inverse,
                                          spike_borderline_threshold,
                                          spike_outlier_threshold,
                                          label_for_normal)
            for label in new_labels:
                labels.append(label)
            # distance = abs((cur_value) - mean_val)
            # if label_for_normal and distance <= std_val:
            #     labels.append(field_name + '_NORMAL')
            # elif std_val < distance <= (2 * std_val):
            #     labels.append(field_name + '_BORDERLINE')
            # elif (2 * std_val) < distance:
            #     labels.append(field_name + '_OUTLIER')
        else:
            key = self._get_group_by_value(input_object, group_by)
            if key in mean_val:
                count = count_val[key]
                if count > 5:
                    new_labels = self._get_labels(cur_value,
                                                  mean_val[key],
                                                  std_val[key],
                                                  stdev,
                                                  stdev_borderline_threshold,
                                                  stdev_outlier_threshold,
                                                  spike,
                                                  spike_inverse,
                                                  spike_borderline_threshold,
                                                  spike_outlier_threshold,
                                                  label_for_normal)
                    for label in new_labels:
                        labels.append(label)

                    # distance = abs((cur_value) - mean_val[key])
                    #
                    # if distance <= std_val[key]:
                    #     labels.append(field_name + '_NORMAL')
                    # elif std_val[key] < distance <= (2 * std_val[key]):
                    #     labels.append(field_name + '_BORDERLINE')
                    # elif (2 * std_val[key]) < distance:
                    #     labels.append(field_name + '_OUTLIER')
                else:
                    labels.append('RARE_KEY_FOR_{0}'.format(field_name))
            else:
                labels.append('UNSEEN_KEY_FOR_{0}'.format(field_name))

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
        # for ngram in self._model:
        #     self._model[ngram] =
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
                sup_count = math.log(self._model[ngram]) + 1
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
    def __init__(self, field_name: str = '', absolute_threshold: int = 10, relative_threshold: float = 0.1,
                 group_by: str = None):
        """
        Constructor
        :param field_name: What field to use
        :param absolute_threshold: Minimum absolute value for occurrences to trigger alert for
        :param relative_threshold: Minimum relative value for occurrences to trigger alert for
        """
        self._mfc = MultinomialFieldCombiner([field_name], absolute_threshold, relative_threshold, group_by=group_by)

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        return self._mfc.build_model(dataset, count_column=count_column)

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
    def __init__(self, field_names: [str] = [], absolute_threshold: int = 10, relative_threshold: float = 0.1,
                 group_by: str = None):
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
                       'field_names': field_names,
                       'group_by': group_by
                       }

    def _get_group_by_value(self, item, group_by):
        if isinstance(group_by, str):
            return str(item[group_by])
        else:
            return "({0})".format(','.join([str(item[k]) for k in group_by]))

    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        pair2count = self._model['pair2count']  # this is used for incremental updates
        group_by_field = self._model['group_by']
        total = 0
        for item in dataset:
            if group_by_field is not None:
                gbv = self._get_group_by_value(item, group_by_field)  # str(item[group_by_field])
                if gbv not in self._model['pair2count']:
                    self._model['pair2count'][gbv] = {'TOTAL': 0}
                pair2count = self._model['pair2count'][gbv]
            combined = [str(item[field]) for field in self._model['field_names']]
            combined = '(' + ','.join(combined) + ')'
            occ_number = 1
            if count_column is not None:
                occ_number = int(item[count_column])
            total += occ_number
            if group_by_field is not None:
                self._model['pair2count'][gbv]['TOTAL'] += occ_number
            if combined not in pair2count:
                pair2count[combined] = occ_number
            else:
                pair2count[combined] += occ_number

        pair2prob = {}
        if group_by_field is None:
            for key in pair2count:
                pair2prob[key] = pair2count[key] / total
        else:
            pair2count = self._model['pair2count']
            for k1 in pair2count:
                pair2prob[k1] = {}
                total = int(pair2count[k1]['TOTAL'])
                for key in pair2count[k1]:
                    pair2prob[k1][key] = pair2count[k1][key] / total

        self._model['pair2count'] = pair2count
        self._model['pair2prob'] = pair2prob

        return self._model

    def __call__(self, item: dict) -> [str]:
        fname = ('_'.join(self._model['field_names'])).upper() + '_PAIR'
        gname = ''
        if self._model['group_by'] is not None:
            gby = self._model['group_by']
            if not isinstance(self._model['group_by'], list):
                gby = [gby]
            gname = '_BASED_ON_{0}'.format('_'.join([str(k).upper() for k in gby]))
        combined = [str(item[field]) for field in self._model['field_names']]
        combined = '(' + ','.join(combined) + ')'

        pair2prob = self._model['pair2prob']
        pair2count = self._model['pair2count']
        group_by = self._model['group_by']
        if group_by is not None:
            gbv = self._get_group_by_value(item, group_by)
            if gbv not in pair2prob:
                return []
            pair2prob = self._model['pair2prob'][gbv]
            pair2count = self._model['pair2count'][gbv]

        if combined not in pair2prob:
            return ['UNSEEN_{0}{1}'.format(fname, gname)]
        else:
            labels = []

            prob = pair2prob[combined]
            cnt = pair2count[combined]

            if cnt < self._model['absolute_threshold']:
                labels.append('LOW_OBS_COUNT_FOR_{0}{1}'.format(fname, gname))
            if prob < self._model['relative_threshold']:
                labels.append('LOW_OBS_PROB_FOR_{0}{1}'.format(fname, gname))
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
