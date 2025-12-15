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

import configparser
import os
import sys
from ast import literal_eval

sys.path.append('')
from osas.pipeline.groom_data import GroomData
from osas.data.datasources import CSVDataSource, Datasource
from osas.pipeline.detect_anomalies import DetectAnomalies
from osas.data.datasources import PySparkDataSource
import json
from collections.abc import Iterator

try:
    from pyspark.sql.functions import pandas_udf, struct, lit
    from pyspark.sql.types import StructType, StructField, StringType, ArrayType, BinaryType, IntegerType, DoubleType
    from pyspark.sql import functions as F
    import pandas as pd
    import pickle
except ImportError:
    pass


class Pipeline:
    ''' base class contains all template methods '''
    env = None
    root_dir = None
    config = None

    def __init__(self, env):
        '''
        init args
        - obj
        - env var
        '''
        # global vars set as env vars
        Pipeline.env = env
        os.environ["OSAS_ENV"] = env  # PROD/STAGE/DEV
        curr_dir = os.path.dirname(os.path.realpath(__file__))
        Pipeline.root_dir = os.path.realpath(os.path.join(curr_dir, "../"))
        self._pipeline = []
        self._detect_anomalies = None
        self._count_column = None

    def load_config(self, config_file, env='DEV'):
        '''
        load configs
        args:
        - obj
        - configfile path
        - env
        '''
        with open(config_file, "r") as f:
            cfg = configparser.RawConfigParser()
            cfg.read_file(f)
            self.config = cfg

        self._scoring_model_name = self.config['AnomalyScoring']['scoring_algorithm']

        if 'GENERAL' in self.config:
            if 'count_column' in self.config['GENERAL']:
                self._count_column = self.config['GENERAL']['count_column']

    def load_model(self, model_file, env='DEV'):
        '''
        Loads a pretrained model for the current configuration
        :param model_file: json file where pretrained model was stored
        :param env: environment type
        :return: None
        '''
        pretrained = json.load(open(model_file))
        gd = GroomData()
        self._pipeline = []
        for sect in self.config:
            print('\t::{0}'.format(sect))
            if 'generator_type' in self.config[sect]:
                self._pipeline.append(gd.from_pretrained(self.config[sect]['generator_type'],
                                                         pretrained['model'][sect]))
        da = DetectAnomalies()
        self._detect_anomalies = da.get_pretrained_model(self._scoring_model_name, json.dumps(pretrained['scoring']))

    def build_pipeline(self, dataset: Datasource, incremental=False) -> dict:
        '''
        Generates a JSON serializable object that contains data for all pretrained label generators
        :param dataset: dataset to train the model on
        :return: serializable dict object
        '''
        gd = GroomData()
        ex_pipeline = self._pipeline
        self._pipeline = []
        final_model = {'model': {}}
        index = 0

        gen_sect = []
        for sect in self.config:
            print('\t::{0}'.format(sect))
            if 'generator_type' in self.config[sect]:
                gen_sect.append(sect)
                for key in self.config[sect]:
                    print("\t\t::{0} = {1}".format(key, self.config[sect][key]))
                if incremental:
                    lg = ex_pipeline[index]
                else:
                    lg = gd.label_generator(self.config[sect]['generator_type'], self.config[sect])
                index += 1
                if not isinstance(dataset, PySparkDataSource):
                    print("\t\t::OBJECT: {0}".format(lg))
                    sys.stdout.write('\t\t::BUILDING MODEL...')
                    sys.stdout.flush()
                    lg_model = gd.build_model(lg, dataset, count_column=self._count_column)
                    final_model['model'][sect] = lg_model
                    sys.stdout.write('done\n')
                self._pipeline.append(lg)

        if isinstance(dataset, PySparkDataSource):

            broadcasted_pipeline = dataset.get_dataframe.sparkSession.sparkContext.broadcast(self._pipeline)
            broadcasted_gd = dataset.get_dataframe.sparkSession.sparkContext.broadcast(gd)
            broadcasted_count_column = dataset.get_dataframe.sparkSession.sparkContext.broadcast(self._count_column)
            
            schema = StructType([
                StructField("lg_index", IntegerType(), nullable=False),
                StructField("model_data", BinaryType(), nullable=False)
            ])

            def train_pipeline_on_partition(pdf_iter: Iterator[pd.DataFrame]):
                pipeline = broadcasted_pipeline.value
                gd = broadcasted_gd.value
                count_column = broadcasted_count_column.value
                for pdf in pdf_iter:
                    rows = []
                    for idx, lg in enumerate(pipeline):
                        ds = CSVDataSource(data=pdf)
                        model = gd.from_pretrained(lg.__class__.__name__, gd.build_model(lg, ds, count_column=count_column))
                        rows.append({"lg_index": idx, "model_data": pickle.dumps(model)})
                    yield pd.DataFrame(rows)


            models_df = dataset.get_dataframe.mapInPandas(train_pipeline_on_partition, schema=schema)
            grouped = models_df.groupBy("lg_index").agg(F.collect_list("model_data").alias("partition_models"))
            partition_models = grouped.collect()

            final_models = {}

            pipeline = []
            for (row, sect) in zip(partition_models, gen_sect):
                lg_index = row["lg_index"]
                pickled_models_for_lg = row["partition_models"]  # list of binary blobs
                models_for_lg = [pickle.loads(model) for model in pickled_models_for_lg]
                final_model['model'][sect], model = gd.merge_models(models_for_lg)
                pipeline.append(model)
            self._pipeline = pipeline

        self(dataset, dest_field_labels='_labels')
        da = DetectAnomalies()
        if not incremental:
            self._detect_anomalies = da.detection_model(self.config['AnomalyScoring']['scoring_algorithm'],
                                                        load_config=False)

        if isinstance(dataset, PySparkDataSource):
            dataset = CSVDataSource(data=dataset.get_dataframe.select('_labels').toPandas())

        # check for classifier scoring and if so, add grouth truth column and classifier as param
        if self.config['AnomalyScoring']['scoring_algorithm'] == 'SupervisedClassifierAnomaly':
            ground_truth_column = self.config['AnomalyScoring']['ground_truth_column']
            classifier = self.config['AnomalyScoring']['classifier']
            # grab function args for model init from rest of conf variables
            init_args = dict(self.config['AnomalyScoring'])
            del init_args['scoring_algorithm']
            del init_args['ground_truth_column']
            del init_args['classifier']
            # convert config values to inferred types, safely
            for k in init_args:
                try:
                    init_args[k] = literal_eval(init_args[k])
                except:
                    # it will be a string otherwise
                    pass
            # build model
            scoring_model = self._detect_anomalies.build_model(dataset,
                                                                ground_truth_column,
                                                                classifier,
                                                                init_args,
                                                                incremental=incremental)
        else:
            scoring_model = self._detect_anomalies.build_model(dataset, incremental=incremental)
        final_model['scoring'] = scoring_model
        return final_model

    def __call__(self, dataset: Datasource, dest_field_labels='labels', dest_field_score='score'):
        if isinstance(dataset, PySparkDataSource):
            df = dataset.get_dataframe
            broadcasted_pipeline = df.sparkSession.sparkContext.broadcast(self._pipeline)

            @pandas_udf(ArrayType(StringType()))
            def process_partition(pdf):
                pipeline = broadcasted_pipeline.value
                return pdf.apply(
                    lambda row: [label for lg in pipeline for label in lg(row.to_dict())],
                    axis=1
                )
            cols = df.columns
            dataset.with_column(dest_field_labels, process_partition(struct(*cols)))
            dataset.with_column('_labels', process_partition(struct(*cols)))
        else:
            all_labels = dataset.apply(lambda item: [label for lg in self._pipeline for label in lg(item)], axis=1)
            dataset[dest_field_labels] = all_labels
            dataset['_labels'] = all_labels
            
        if self._detect_anomalies is None:
            return
        
        if isinstance(dataset, PySparkDataSource):
            broadcasted_detect_anomalies = dataset.get_dataframe.sparkSession.sparkContext.broadcast(self._detect_anomalies)
            schema = dataset.get_dataframe.schema
            schema = schema.add(StructField(dest_field_score, DoubleType(), nullable=True))
            def process_partition(pdf_iter: Iterator[pd.DataFrame]):
                detect_anomalies = broadcasted_detect_anomalies.value
                for pdf in pdf_iter:
                    pdf[dest_field_score] = detect_anomalies(CSVDataSource(data=pdf))
                    yield pdf
                    
            scored_df = dataset.get_dataframe.withColumn(dest_field_score, lit(None).cast("double")).mapInPandas(process_partition, schema=schema)
            print(scored_df)
            dataset.set_dataframe(scored_df)
            return

        scores = self._detect_anomalies(dataset)
        dataset[dest_field_score] = scores


if __name__ == '__main__':
    p = Pipeline('DEV')
    p.load_config('tests/pipeline_test.conf')
    import time

    ts1 = time.time()
    datasource = CSVDataSource('tests/test_small.csv')
    ts2 = time.time()
    pipeline_model = p.build_pipeline(datasource)
    ts3 = time.time()
    p(datasource)
    ts4 = time.time()
    json.dump(pipeline_model, open('tests/pipeline.json', 'w'), indent=4)
    for item in datasource[:10]:
        print(item)
        print()
        print()

    print(
        "Timing:\n\tLoad dataset: {0}\n\tBuild pipeline: {1}\n\tApply models:{2}\n\tDataset size: {3} entries\n".format(
            ts2 - ts1, ts3 - ts2, ts4 - ts3, len(datasource)))

    # load
    p = Pipeline('DEV')
    p.load_config('tests/pipeline_test.conf')
    p.load_model('tests/pipeline.json')
    p(datasource)

    for item in datasource[:10]:
        print(item)
        print()
        print()
