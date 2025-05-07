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
from typing import Any

import pandas as pd
import numbers

sys.path.append('')

from osas.core.interfaces import Datasource, DataColumn


class CSVDataColumn(DataColumn):
    def __init__(self, data: pd.DataFrame):
        super(CSVDataColumn, self).__init__()
        self._data = data

    def mean(self) -> float:
        return self._data.mean()

    def std(self) -> float:
        return self._data.std()

    def min(self) -> any:
        return self._data.min()

    def max(self) -> any:
        return self._data.max()

    def unique(self) -> list:
        return pd.unique(self._data)

    def value_counts(self) -> dict:
        return self._data.value_counts()

    def tolist(self) -> list:
        return list(self._data)

    def apply(self, func) -> int:
        self._data.apply(func)

    def __len__(self) -> int:
        return len(self._data)

    def __getitem__(self, index: int) -> dict:
        return self._data[index]

    def __setitem__(self, index: int, value: Any) -> dict:
        self._data.iloc[index] = value


class CSVDataSource(Datasource):

    def __init__(self, filename: str):
        super().__init__()
        self._data = pd.read_csv(filename)

    def __len__(self):
        return len(self._data)

    def __getitem__(self, item: int):
        if isinstance(item, numbers.Integral):
            return self._data.iloc[item].to_dict()
        elif isinstance(item, slice):
            rez = []
            for ii in range(item.start or 0, item.stop or len(self), item.step or 1):
                rez.append(self._data.iloc[ii].to_dict())
            return rez
        elif isinstance(item, str):
            return CSVDataColumn(self._data[item])
        else:
            raise NotImplemented

    def __setitem__(self, key: str, value: any):
        self._data[key] = value

    def apply(self, func, axis: int = 0) -> int:
        return self._data.apply(func, axis=axis)

    def save(self, file) -> None:
        self._data.to_csv(file)


if __name__ == '__main__':
    tmp = CSVDataSource('corpus/test.csv')
    print(tmp[:10])
    cnt = 0
    from ipdb import set_trace

    set_trace()
    for item in tmp:
        cnt += 1
        print(item)
        if cnt == 10:
            break
