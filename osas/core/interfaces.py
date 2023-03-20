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

from typing import Union, Any
from abc import abstractmethod


class DatasourceIterator:
    def __init__(self, datasource):
        self._ds = datasource
        self._index = 0

    def __next__(self):
        if self._index < len(self._ds):
            rez = self._ds[self._index]
            self._index += 1
            return rez
        else:
            raise StopIteration


class DataColumn:
    def __init__(self):
        pass

    @abstractmethod
    def mean(self) -> float:
        """Computes mean for numerical columns"""
        pass

    @abstractmethod
    def std(self) -> float:
        """Computes standard deviation for numerical columns"""
        pass

    @abstractmethod
    def min(self) -> any:
        """Computes minumum value for numerical columns"""
        pass

    @abstractmethod
    def max(self) -> any:
        """Computes minumum value for numerical columns"""
        pass

    @abstractmethod
    def unique(self) -> list:
        """Computes unique values for columns"""
        pass

    @abstractmethod
    def value_counts(self) -> dict:
        """Computes histogram values for columns"""
        pass

    @abstractmethod
    def tolist(self) -> list:
        """Computes """
        pass

    @abstractmethod
    def apply(self, func) -> int:
        """
        Apply lambda function
        :param func: function to apply
        :return:
        """
        pass

    @abstractmethod
    def __len__(self) -> int:
        """Returns the number of items in the collection"""
        pass

    @abstractmethod
    def __getitem__(self, index: int) -> dict:
        """Returns an item as a dictionary
        :param index - the index of the element
        """
        pass

    @abstractmethod
    def __setitem__(self, index: int, value: Any) -> dict:
        """Sets the value for an item
        :param index - the index of the element
        """
        pass

    def __iter__(self):
        return DatasourceIterator(self)


class Datasource:
    def __init__(self):
        pass

    @abstractmethod
    def __len__(self) -> int:
        """Returns the number of items in the collection"""
        pass

    @abstractmethod
    def __getitem__(self, index: int) -> dict:
        """Returns an item as a dictionary
        :param index - the index of the element
        """
        pass

    @abstractmethod
    def __setitem__(self, key: str, value: any):
        """
        Create or set a column
        :param key: column name
        :param value: values
        :return:
        """
        pass

    def __iter__(self):
        return DatasourceIterator(self)

    @abstractmethod
    def apply(self, func, axis: int = 0) -> int:
        """
        Apply lambda function
        :param func: function to apply
        :param axis: 0-column, 1-row; default=0
        :return:
        """
        pass

    @abstractmethod
    def save(self, file_handle) -> None:
        """
        Save the data into csv format
        :param file_handle: open file handle for writing
        :return: None
        """


class LabelGenerator:
    def __init__(self):
        pass

    @abstractmethod
    def __call__(self, input_object: dict) -> [str]:
        """
        Generate specific labels for the dataset entry
        :param input_object: an entry in the dataset
        :return: list of labels generated for this input object
        """
        pass

    @abstractmethod
    def build_model(self, dataset: Datasource, count_column: str = None) -> dict:
        """
        This model should generate a model on the input
        :param dataset: the dataset used to generate the model
        :param count_column: use this column for clustered data. If not set, event count will be 1
        :return: This should be a json serializable object
        """
        pass

    @staticmethod
    def from_pretrained(pretrained: str) -> object:
        """
        :param pretrained: dictionary holding pretrained model
        :return: New instance
        """
        pass


class AnomalyDetection:
    def __init__(self):
        pass

    @abstractmethod
    def build_model(self, dataset: Datasource, incremental: bool = False) -> dict:
        """
        This model should generate a model on the input
        :param dataset: the dataset used to generate the model
        :param incremental: perform incremental update
        :return: This should be a json serializable object
        """
        pass

    @abstractmethod
    def __call__(self, dataset: Datasource, verbose=True) -> [float]:
        """
        Scores a dataset with anomaly scores
        :param dataset: the dataset to score
        :return: an anomaly score for each example in the dataset
        """
        pass
