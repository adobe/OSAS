import configparser
import sys
import hashlib
import io
import json
import time

sys.path.append('')

from src.osas.pipeline import Pipeline
from src.osas.pipeline import DetectAnomalies
from src.osas.pipeline import GroomData


class OSASConfig:
    def __init__(self, configparser: configparser.ConfigParser):
        '''
        Create a new instance of OSAS configuration. If you don't want to manually use configparser to parse the input, use one of the helper methods: from_file or from_string
        @param configparser - instance of type RawConfigParser
        '''
        self._config = configparser
        # compute md5 of conf file
        bw = io.StringIO()
        configparser.write(bw)
        bw.flush()
        bw.seek(0)
        bb = bw.read().encode('utf-8')
        self._md5 = hashlib.md5(bb).hexdigest()

    @staticmethod
    def from_file(filename: str):
        '''
        Create a new config instance using the specified filename

        @param filename: path to file
        '''

        cfg = configparser.ConfigParser()
        with open(filename, 'r') as f:
            cfg.read_file(f)

        oc = OSASConfig(cfg)
        return oc

    @staticmethod
    def from_string(string: str):
        '''
        Create a new config instance using the specified configuration string

        @param string: configuration string
        '''
        cfg = configparser.RawConfigParser()
        cfg.read_string(string)
        oc = OSASConfig(cfg)
        return oc

    def md5(self):
        return self._md5

    @property
    def config(self):
        return self._config


class OSASPretrainedModel:
    def __init__(self, string: str):
        self._json = json.loads(string)
        self._md5 = hashlib.md5(string.encode('utf-8')).hexdigest()

    @staticmethod
    def from_file(filename: str):
        return OSASPretrainedModel(open(filename).read())

    @staticmethod
    def from_string(string: str):
        return OSASPretrainedModel(string)

    def md5(self):
        return self._md5

    @property
    def json(self):
        return self._json


osas_instances = {}


class OSAS:
    def __init__(self, conf: OSASConfig, model: OSASPretrainedModel):
        self._pipeline = []
        gd = GroomData()
        scoring_model_name = conf.config['AnomalyScoring']['scoring_algorithm']
        for sect in conf.config:
            if 'generator_type' in conf.config[sect]:
                self._pipeline.append(gd.from_pretrained(conf.config[sect]['generator_type'],
                                                         model.json['model'][sect]))
        da = DetectAnomalies()
        self._detect_anomalies = da.get_pretrained_model(scoring_model_name, json.dumps(model.json['scoring']))

    @staticmethod
    def get_instance(conf: OSASConfig, model: OSASPretrainedModel):
        total_hash = '{0}_{1}'.format(conf.md5(), model.md5())
        if total_hash not in osas_instances:
            osas_instance = OSAS(conf, model)
            osas_instances[total_hash] = osas_instance
            return osas_instance
        else:
            return osas_instances[total_hash]

    def __call__(self, row_dict: dict):
        label_list = []
        for lg in self._pipeline:
            llist = lg(row_dict)
            for label in llist:
                label_list.append(label)
        # create a dummy entry

        dummy_ds = [{'_labels': label_list}]
        score = self._detect_anomalies(dummy_ds, verbose=False)
        return {
            'labels': label_list,
            'score': score
        }


if __name__ == '__main__':
    cfg = OSASConfig.from_file('tests/model.conf')
    print(cfg.md5())
    mdl = OSASPretrainedModel.from_file('tests/model.json')
    print(mdl.md5())
    time_start = time.time()
    osas = OSAS.get_instance(cfg, mdl)
    time_first_call = time.time()
    osas = OSAS.get_instance(cfg, mdl)
    time_second_call = time.time()
    t1 = time_first_call - time_start
    t2 = time_second_call - time_first_call
    print("Initial instance creation took {0:.8f} seconds".format(t1))
    print("Second call took {0:.8f} seconds".format(t2))
    print("Speedup was {0:.3f}".format(t1 / t2))
    print(osas({
        'countries': 'Somalia',
    }))
