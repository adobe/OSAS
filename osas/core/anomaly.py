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
from sklearn.ensemble import RandomForestClassifier
import json
import pickle
import base64

sys.path.append('')
from osas.core.interfaces import AnomalyDetection, Datasource


class IFAnomaly(AnomalyDetection):
    """
    Uses LOF to detect anomalies
    """

    def __init__(self):
        super().__init__()
        self._model = None
        self._data_encoder = None
        self._decompose = None

    def build_model(self, dataset: Datasource) -> dict:
        data_encoder = MultiLabelBinarizer()
        labels = []
        for item in dataset:
            labels.append(item['_labels'])
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

    def __call__(self, dataset: Datasource) -> [float]:

        labels = []
        for item in dataset:
            labels.append(item['_labels'])
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

    def build_model(self, dataset: Datasource) -> dict:
        data_encoder = MultiLabelBinarizer()
        labels = []
        for item in dataset:
            labels.append(item['_labels'])
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

    def __call__(self, dataset: Datasource) -> [float]:

        labels = []
        for item in dataset:
            labels.append(item['_labels'])
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

    def build_model(self, dataset: Datasource) -> dict:
        data_encoder = MultiLabelBinarizer()
        labels = []
        for item in dataset:
            labels.append(item['_labels'])
        data_encoded = data_encoder.fit_transform(labels)
        self._data_encoder = data_encoder

        decompose = TruncatedSVD(n_components=4, n_iter=50, random_state=42)
        decompose.fit(data_encoded)

        self._model = decompose

        model = {'encoder': self._data_encoder,
                 'SVD': self._model}

        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model

    def __call__(self, dataset: Datasource) -> [float]:

        labels = []
        for item in dataset:
            labels.append(item['_labels'])
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

    def build_model(self, dataset: Datasource) -> dict:

        model = {
            '1': {'TOTAL': 0},
            '2': {'TOTAL': 0},
            '3': {'TOTAL': 0}
        }
        # for clarity, this code is written explicitly
        for item in tqdm.tqdm(dataset, ncols=100, desc="\tbuilding model"):
            tags = list(sorted(item['_labels']))
            # unigrams
            grams = model['1']
            for ii in range(len(tags)):
                key = '(' + str(tags[ii]) + ')'
                if key in grams:
                    grams[key]['COUNT'] += 1
                else:
                    grams[key] = {'COUNT': 1}
                grams['TOTAL'] += 1

            # bigrams
            grams = model['2']

            for ii in range(len(tags) - 1):
                for jj in range(ii + 1, len(tags)):
                    key = '(' + str(tags[ii]) + ',' + str(tags[jj]) + ')'
                    if key in grams:
                        grams[key]['COUNT'] += 1
                    else:
                        grams[key] = {'COUNT': 1}
                    grams['TOTAL'] += 1

            # trigrams
            grams = model['3']

            for ii in range(len(tags) - 2):
                for jj in range(ii + 1, len(tags) - 1):
                    for kk in range(jj + 1, len(tags)):
                        key = '(' + str(tags[ii]) + ',' + str(tags[jj]) + ',' + str(tags[kk]) + ')'
                        if key in grams:
                            grams[key]['COUNT'] += 1
                        else:
                            grams[key] = {'COUNT': 1}
                        grams['TOTAL'] += 1

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

    def __call__(self, dataset: Datasource) -> [float]:

        def _build_feats(tags):
            feats = []
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
            return new_feats

        def _compute_score(ngram2score, tags, handle_unseen=True):
            feats = _build_feats(tags)

            score = 0
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
                        score += 100  # -math.log(1e-8)
            return score

        scores = []
        for item in tqdm.tqdm(dataset, ncols=100, desc="\tscoring data"):
            scores.append(_compute_score(self._model, item['_labels']))

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
        self._model = None
        self._encoder = None

    def build_model(self, dataset: Datasource, ground_truth_column: str, classifier: str) -> dict:
        labels = []
        model_ground_truths = []
        encoder = MultiLabelBinarizer()
        for item in dataset:
            labels.append(item['_labels'])
            # TODO: for now, only using "clean" and "bad" as labels.
            # need to find a new way to generalize on all types of labels
            if item[ground_truth_column] == 'clean':
                model_ground_truths.append(0)
            elif item[ground_truth_column] == 'bad':
                model_ground_truths.append(1)
            else:
                raise Exception('invalid ground truth value: ' + item[ground_truth_column])
        labels_enc = encoder.fit_transform(labels)
        self._encoder = encoder

        rf = RandomForestClassifier(n_estimators=100, random_state=42) # hyperparameters
        rf.fit(labels_enc, model_ground_truths)

        self._model = rf
        model = {
            'encoder': self._encoder,
            'classifier': self._model
        }
        out_model = base64.b64encode(pickle.dumps(model)).decode('ascii')
        model = {'model': out_model}
        return model
        
    def __call__(self, dataset: Datasource) -> [float]:
        labels = []
        for item in dataset:
            labels.append(item['_labels'])
        labels_enc = self._encoder.transform(labels)
    
        preds = self._model.predict_proba(labels_enc)
        # hard-coded for "bad" index right now
        preds = [pred[1] for pred in preds]
        # return list of probabilities of the events being an anomaly
        # print(self._model.classes_)
        # print(len(preds))
        # print(preds)
        return preds
       
    @staticmethod
    def from_pretrained(pretrained: str) -> AnomalyDetection:
        tmp = json.loads(pretrained)
        pre_model = pickle.loads(base64.b64decode(tmp['model']))
        model = SupervisedClassifierAnomaly()
        model._encoder = pre_model['encoder']
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
