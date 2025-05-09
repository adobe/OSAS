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
import numpy as np
import tqdm
from sklearn.preprocessing import MultiLabelBinarizer
from sklearn.decomposition import TruncatedSVD
from sklearn.neighbors import LocalOutlierFactor
from sklearn.ensemble import IsolationForest
import json
import pickle
import base64
import importlib

sys.path.append('')
from osas.core.interfaces import AnomalyDetection, Datasource
from collections import Counter


class IFAnomaly(AnomalyDetection):
    """
    Uses LOF to detect anomalies
    """

    def __init__(self):
        super().__init__()
        self._model = None
        self._data_encoder = None
        self._decompose = None

    def build_model(self, dataset: Datasource, incremental=False) -> dict:
        data_encoder = MultiLabelBinarizer()
        labels = dataset.apply(lambda item: item['_labels'], axis=1)

        data_encoded = data_encoder.fit_transform(labels)
        self._data_encoder = data_encoder

        decompose = TruncatedSVD(n_components=4, n_iter=7, random_state=42)
        data_decomposed = decompose.fit_transform(data_encoded)
        self._decompose = decompose

        iso_forest = IsolationForest(random_state=0, n_jobs=4)
        iso_forest.fit(data_decomposed)

        self._model = iso_forest

        model = {'encoder': self._data_encoder,
                 'SVD': self._decompose,
                 'iso_forest': self._model
                 }
        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model

    def __call__(self, dataset: Datasource, verbose=True) -> [float]:

        labels = dataset.apply(lambda item: item['_labels'])
        data_encoded = self._data_encoder.transform(labels)
        data_decomposed = self._decompose.transform(data_encoded)
        scores = self._model.score_samples(data_decomposed)

        return -scores

    @staticmethod
    def from_pretrained(pretrained: str) -> AnomalyDetection:
        tmp = json.loads(pretrained)
        pre_model = pickle.loads(base64.b64decode(tmp['model']))
        model = IFAnomaly()
        model._data_encoder = pre_model['encoder']
        model._decompose = pre_model['SVD']
        model._model = pre_model['iso_forest']

        return model


class LOFAnomaly(AnomalyDetection):
    """
    Uses LOF to detect anomalies
    """

    def __init__(self):
        super().__init__()
        self._model = None
        self._data_encoder = None
        self._decompose = None

    def build_model(self, dataset: Datasource, incremental=False) -> dict:
        data_encoder = MultiLabelBinarizer()
        labels = dataset.apply(lambda item: item['_labels'], axis=1)

        data_encoded = data_encoder.fit_transform(labels)
        self._data_encoder = data_encoder

        decompose = TruncatedSVD(n_components=4, n_iter=7, random_state=42)
        data_decomposed = decompose.fit_transform(data_encoded)
        self._decompose = decompose

        lof = LocalOutlierFactor(n_neighbors=10, n_jobs=4, novelty=True)
        lof.fit(data_decomposed)

        self._model = lof

        model = {'encoder': self._data_encoder,
                 'SVD': self._decompose,
                 'LOF': self._model
                 }

        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model

    def __call__(self, dataset: Datasource, verbose=True) -> [float]:

        labels = dataset.apply(lambda item: item['_labels'], axis=1)
        data_encoded = self._data_encoder.transform(labels)
        data_decomposed = self._decompose.transform(data_encoded)
        scores = self._model.score_samples(data_decomposed)

        return -scores

    @staticmethod
    def from_pretrained(pretrained: str) -> AnomalyDetection:
        tmp = json.loads(pretrained)
        pre_model = pickle.loads(base64.b64decode(tmp['model']))
        model = LOFAnomaly()
        model._data_encoder = pre_model['encoder']
        model._decompose = pre_model['SVD']
        model._model = pre_model['LOF']

        return model


class SVDAnomaly(AnomalyDetection):
    """
    Uses an autoencoder to compute anomaly score
    """

    def __init__(self):
        super().__init__()
        self._data_encoder = None
        self._model = None

    def build_model(self, dataset: Datasource, incremental=False) -> dict:
        labels = dataset.apply(lambda item: [label for label in item['_labels'] if isinstance(label, str)], axis=1)
        if not incremental:
            data_encoder = MultiLabelBinarizer()
            data_encoded = data_encoder.fit_transform(labels)
        else:
            data_encoder = self._data_encoder
            data_encoded = data_encoder.transform(labels)
        self._data_encoder = data_encoder
        if not incremental:
            decompose = TruncatedSVD(n_components=4, n_iter=50, random_state=42)
            decompose.fit(data_encoded)
        else:
            decompose = self._model
            decompose.partial_fit(data_encoded)

        self._model = decompose

        model = {'encoder': self._data_encoder,
                 'SVD': self._model}

        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model

    def __call__(self, dataset: Datasource, verbose=True) -> [float]:

        labels = dataset.apply(lambda item: item['_labels'], axis=1)
        data_encoded = self._data_encoder.transform(labels)
        data_decomposed = self._model.transform(data_encoded)
        data_reconstruct = self._model.inverse_transform(data_decomposed)

        difference = data_encoded - data_reconstruct
        power = np.sum(difference ** 2, axis=1)
        error = np.sqrt(power)

        return error

    @staticmethod
    def from_pretrained(pretrained: str) -> AnomalyDetection:
        tmp = json.loads(pretrained)
        pre_model = pickle.loads(base64.b64decode(tmp['model']))
        model = SVDAnomaly()
        model._data_encoder = pre_model['encoder']
        model._model = pre_model['SVD']

        return model


class StatisticalNGramAnomaly(AnomalyDetection):
    """
    Uses an autoencoder to compute anomaly score
    """

    def __init__(self):
        super().__init__()
        self._model = None

    def process_item(self, item):

        local_counts = {
            '1': Counter(),
            '2': Counter(),
            '3': Counter(),
            'totals': {'1': 0, '2': 0, '3': 0}
        }

        tags = item['_labels']
        string_tags = []
        for tag in tags:
            try:
                tag = float(tag)
                continue
            except ValueError as e:
                if 'string' in str(e):
                    string_tags.append(tag)

        tags = string_tags
        tags = list(sorted(tags))

        for gram_type in ['1', '2', '3']:
            for tag in tags:
                key = f"({tag})"
                local_counts[gram_type][key] += 1
                local_counts['totals'][gram_type] += 1

        return local_counts

    def build_model(self, dataset: Datasource, incremental=False) -> dict:
        if not incremental:
            model = {
                '1': {'TOTAL': 0},
                '2': {'TOTAL': 0},
                '3': {'TOTAL': 0}
            }
        else:
            model = self._model
        # for clarity, this code is written explicitly

        results = dataset.apply(self.process_item, axis=1)
        for result in results:
            for gram_size in ['1', '2', '3']:
                for (key, cnt) in result[gram_size].items():
                    if key not in model[gram_size]:
                        model[gram_size][key] = {'COUNT': 0, 'PROB': 0, 'NEG_LOG_PROB': 0}
                    model[gram_size][key]['COUNT'] += cnt

                model[gram_size]['TOTAL'] += result['totals'][gram_size]

        # convert to probs and log-probs
        for g in ['1', '2', '3']:
            grams = model[g]
            total = grams['TOTAL']
            for key in grams:
                if key != 'TOTAL':
                    grams[key]['PROB'] = grams[key]['COUNT'] / total
                    grams[key]['NEG_LOG_PROB'] = -np.log(grams[key]['PROB'])
        self._model = model

        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model

    def __call__(self, dataset: Datasource, verbose=True) -> [float]:

        def _build_feats(tags):
            feats = []
            string_tags = []
            perp_score = 0
            for tag in tags:
                if isinstance(tag, str):
                    string_tags.append(tag)
                else:
                    perp_score += tag
            tags = string_tags
            tags = list(sorted(tags))

            for ii in range(len(tags)):
                feats.append([tags[ii]])
            for ii in range(len(tags) - 1):
                for jj in range(ii + 1, len(tags)):
                    feats.append([tags[ii], tags[jj]])

            for ii in range(len(tags) - 2):
                for jj in range(ii + 1, len(tags) - 1):
                    for kk in range(jj + 1, len(tags)):
                        feats.append([tags[ii], tags[jj], tags[kk]])
            new_feats = []
            for feat in feats:
                mid = "(" + ",".join(feat) + ")"
                new_feats.append(mid)
            return new_feats, perp_score

        def _compute_score(ngram2score, tags, handle_unseen=True) -> float:
            feats, perp_score = _build_feats(tags)

            score = 0.0
            for feat in feats:
                found = False
                if feat in ngram2score['1']:
                    score += ngram2score['1'][feat]['NEG_LOG_PROB']
                    found = True
                elif feat in ngram2score['2']:
                    score += ngram2score['2'][feat]['NEG_LOG_PROB']
                    found = True
                elif feat in ngram2score['3']:
                    score += ngram2score['3'][feat]['NEG_LOG_PROB']
                    found = True
                if not found:
                    if handle_unseen:
                        import math
                        score += -math.log(1e-8)
            return score + perp_score

        print('Computing anomaly scores')
        scores = dataset.apply(lambda x: _compute_score(self._model, x['_labels']), axis=1)
        return scores

    @staticmethod
    def from_pretrained(pretrained: str) -> AnomalyDetection:
        tmp = json.loads(pretrained)
        pre_model = pickle.loads(base64.b64decode(tmp['model']))
        model = StatisticalNGramAnomaly()
        model._model = pre_model

        return model


class SupervisedClassifierAnomaly(AnomalyDetection):
    def __init__(self):
        super().__init__()
        self.BINARY_GROUND_TRUTHS1 = {'clean', 'bad'}
        self.BINARY_GROUND_TRUTHS2 = {0, 1}
        self.BINARY_IND_TO_GROUND_TRUTH1 = ['clean', 'bad']
        self.BINARY_IND_TO_GROUND_TRUTH2 = [0, 1]

        self._model = None
        self._encoder = None
        self._is_binary_preds = False
        self._ind_to_ground_truth = None

    def build_model(self, dataset: Datasource, ground_truth_column: str, classifier: str, init_args: dict,
                    incremental=False) -> dict:

        labels = dataset.apply(lambda item: item['_labels'], axis=1)
        ground_truth_values = set(dataset.apply(lambda item: item[ground_truth_column], axis=1))

        if not incremental:
            encoder = MultiLabelBinarizer()
            labels_enc = encoder.fit_transform(labels)
        else:
            encoder = self._encoder
            labels_enc = encoder.transform(labels)

        # set binary preds
        if ground_truth_values == self.BINARY_GROUND_TRUTHS1:
            # all grouth truth labels either clean or bad
            self._is_binary_preds = True
            ind_to_ground_truth = self.BINARY_IND_TO_GROUND_TRUTH1  # set bad to index 1
        elif ground_truth_values == self.BINARY_GROUND_TRUTHS2:
            # all grouth truth labels either 0 or 1
            self._is_binary_preds = True
            ind_to_ground_truth = self.BINARY_IND_TO_GROUND_TRUTH2  # set 1 to index 1
        else:
            # ground truth labels can be anything
            self._is_binary_preds = False
            ind_to_ground_truth = list(ground_truth_values)

        # convert ground truth values to indices
        ground_truth_to_ind = dict()
        for i in range(len(ind_to_ground_truth)):
            ground_truth_to_ind[ind_to_ground_truth[i]] = i

        model_ground_truths = dataset.apply(lambda item: ground_truth_to_ind[item[ground_truth_column]], axis=1)

        # get the classifier
        if not incremental:
            try:
                clf_parts = classifier.split('.')
                assert clf_parts[0] == 'sklearn'
                sk_pkg = importlib.import_module('{:s}.{:s}'.format(clf_parts[0], clf_parts[1]))
                clf_class = getattr(sys.modules[sk_pkg.__name__], clf_parts[2])
            except:
                raise Exception(
                    'expected classifier to be in sklearn package format: sklearn.<package>.<class> (ex. sklearn.linear_model.LogisiticRegression)')
            clf = clf_class(**init_args)  # dict unpacking for init args
            clf.fit(labels_enc, model_ground_truths)
        else:
            clf = self._model
            clf.partial_fit(labels_enc, model_ground_truths)

        # return model
        self._encoder = encoder
        self._ind_to_ground_truth = ind_to_ground_truth
        self._model = clf
        model = {
            'encoder': self._encoder,
            'ind_to_ground_truth': ind_to_ground_truth,
            'is_binary_preds': self._is_binary_preds,
            'classifier': self._model
        }
        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model

    def __call__(self, dataset: Datasource, verbose=True) -> [float]:
        labels = dataset.apply(lambda item: item['_labels'], axis=1)
        labels_enc = self._encoder.transform(labels)

        preds = self._model.predict_proba(labels_enc)
        if self._is_binary_preds:
            # return the "bad" prob
            preds = [pred[1] for pred in preds]
        else:
            # return the class with most prob
            preds = [self._ind_to_ground_truth[np.argmax(pred)] for pred in preds]
        return preds

    @staticmethod
    def from_pretrained(pretrained: str) -> AnomalyDetection:
        tmp = json.loads(pretrained)
        pre_model = pickle.loads(base64.b64decode(tmp['model']))
        model = SupervisedClassifierAnomaly()
        model._encoder = pre_model['encoder']
        model._ind_to_ground_truth = pre_model['ind_to_ground_truth']
        model._is_binary_preds = pre_model['is_binary_preds']
        model._model = pre_model['classifier']

        return model


if __name__ == "__main__":
    from osas.data.datasources import CSVDataSource

    data_source = CSVDataSource('corpus/hubble_test_tags.csv')


    def coverter(x):
        return ast.literal_eval(x)


    data_source._data['_labels'] = data_source._data['_labels'].apply(lambda x: coverter(x))

    model = StatisticalNGramAnomaly()
    tmp = model.build_model(data_source)
    tmp = json.dumps(tmp)
    model2 = StatisticalNGramAnomaly.from_pretrained(tmp)
    scores = model(data_source)

    scores2 = model2(data_source)
    import operator

    dd = {}
    from ipdb import set_trace

    for ex, score in zip(data_source, scores):
        dd[",".join(ex['_labels'])] = score
    sorted_x = sorted(dd.items(), key=operator.itemgetter(1))

    set_trace()
