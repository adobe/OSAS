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
import warnings
import threading

import pandas as pd
import numbers

sys.path.append('')

from osas.core.interfaces import Datasource, DataColumn

try:
    import os
    os.environ['PYARROW_IGNORE_TIMEZONE'] = '1'
    from pyspark.sql import DataFrame as SparkDataFrame, SparkSession
    from pyspark.sql import functions as F, Row
    from pyspark.sql.types import *
    from pyspark.sql.window import Window
    import pyspark.pandas as ps
    _HAS_PYSPARK = True
except ImportError:
    SparkDataFrame = SparkSession = None
    _HAS_PYSPARK = False


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
        return self._data.apply(lambda row: func(row.to_dict()), axis=axis)

    def save(self, file) -> None:
        with open(file, 'w') as f:
            self._data.to_csv(f)

    def groupby(self, column_name: str, func):
        return self._data.groupby(column_name).agg(func).to_dict()


if _HAS_PYSPARK:
    class PySparkDataSource(Datasource):
        _spark_session = None
        _lock = threading.Lock()

        @classmethod
        def get_or_create_spark_session(cls, spark_conf_path: str = None):
            with cls._lock:
                if cls._spark_session is None:
                    if spark_conf_path:
                        import configparser
                        config = configparser.ConfigParser()
                        config.read(spark_conf_path)
                        builder = SparkSession.builder

                        for key, value in config.items('spark'):
                            builder = builder.config(key, value)
                        cls._spark_session = builder.getOrCreate()
                        return cls._spark_session
                    
                    cls._spark_session = (
                        SparkSession.builder
                        .appName("OSAS")
                        .config("spark.sql.shuffle.partitions", "10")
                        .config("spark.default.parallelism", "10")
                        .config("spark.memory.fraction", "0.8")
                        .config("spark.memory.storageFraction", "0.3")
                        .master("local[*]")
                        .getOrCreate()
                    )
                return cls._spark_session

        def __init__(self, file_path: str, spark_conf_path=None, **options):
            super().__init__()
            self._spark = self.get_or_create_spark_session(spark_conf_path)

            # Read CSV file with optimized settings
            self._data = (
                self._spark.read
                .option("inferSchema", "true")
                .option("header", "true")
                .option("maxColumns", "10000")
                .option("maxCharsPerColumn", "10000")
                .csv(file_path, **options)
            )

            # Cache the DataFrame for better performance
            self._data.cache()

            # Add a unique identifier column for efficient row access
            self._data = self._data.withColumn("_row_id", F.monotonically_increasing_id())

            # Optimize partitions based on data size
            num_partitions = min(10, max(1, self._data.count() // 1000))
            if self._data.rdd.getNumPartitions() > num_partitions:
                self._data = self._data.repartition(num_partitions)

        def __len__(self):
            return self._data.count()

        def __getitem__(self, item: Any):
            # Single-row access by integer index - using direct filtering on _row_id
            if isinstance(item, numbers.Integral):
                warnings.warn(
                    "Accessing PySpark Datasource by index is not optimized. Consider using apply instead.",
                    UserWarning,
                    stacklevel=2
                )
                return (
                    self._data
                    .filter(F.col("_row_id") == item)
                    .drop("_row_id")
                    .first()
                    .asDict()
                )

            # Slice access: start:stop:step - using direct filtering on _row_id
            elif isinstance(item, slice):
                start, stop, step = item.indices(self.__len__())
                return (
                           self._data
                           .filter((F.col("_row_id") >= start) & (F.col("_row_id") < stop))
                           .drop("_row_id")
                           .collect()
                       )[::step]

            # Column access by name
            elif isinstance(item, str):
                return PySparkDataColumn(self._data.select(item))

            else:
                raise NotImplementedError(f"Unsupported index type: {type(item)}")

        @classmethod
        def cleanup(cls):
            # Cleanup method to stop the SparkSession
            if cls._spark_session is not None:
                cls._spark_session.stop()
                cls._spark_session = None

        @staticmethod
        def infer_type(val):
            """Infer PySpark type from a value."""
            if isinstance(val, int):
                return IntegerType()
            elif isinstance(val, float):
                return DoubleType()
            elif isinstance(val, bool):
                return BooleanType()
            elif isinstance(val, str):
                return StringType()
            elif isinstance(val, list):
                if len(val) == 0:
                    return ArrayType(StringType(), True)
                element_type = PySparkDataSource.infer_type(val[0])
                return ArrayType(element_type, True)
            else:
                raise TypeError(f"Unsupported type: {type(val)}")

        def __setitem__(self, key: str, value: list):
            dtype = self.infer_type(value[0])
            if key in self._data.columns:
                self._data = self._data.drop(key)

            if dtype == DoubleType():
                value = [float(v) for v in value]

            # Create a new DataFrame with the new column
            new_df = self._data.sparkSession.createDataFrame(
                [(i, v) for i, v in enumerate(value)],
                ["_row_id", key]
            )

            # Join with the original DataFrame
            self._data = (
                self._data
                .join(new_df, on="_row_id")
            )

        def apply(self, func, axis: int = 0) -> Any:
            return self._data.rdd.map(func).collect()

        def save(self, file: str, format: str = 'csv') -> None:
            if str(file).endswith('.csv'):
                warnings.warn("Pass directory name for CSV files. The file will be saved in the directory.", UserWarning)

            save_data = self._data
            for col in save_data.columns:
                if isinstance(save_data.schema[col].dataType, ArrayType):
                    # Convert ArrayType column to string
                    save_data = save_data.withColumn(col, F.col(col).cast("string"))
            save_data.write.mode('overwrite').option("header", "true").csv(file)

        def groupby(self, column_name: str, func):
            return self._data.groupBy(column_name).agg(func).collect()


    class PySparkDataColumn(DataColumn):
        def __init__(self, dataframe: SparkDataFrame):
            super(PySparkDataColumn, self).__init__()
            self._data = dataframe
            self._col_name = dataframe.columns[0]

        def mean(self) -> float:
            return float(self._data.select(F.mean(self._col_name)).first()[0])

        def std(self) -> float:
            return float(self._data.select(F.stddev(self._col_name)).first()[0])

        def min(self) -> Any:
            return self._data.select(F.min(self._col_name)).first()[0]

        def max(self) -> Any:
            return self._data.select(F.max(self._col_name)).first()[0]

        def unique(self) -> list[any]:
            return [row[0] for row in self._data.select(self._col_name).distinct().collect()]

        def value_counts(self) -> dict:
            return dict(
                self._data
                .groupBy(self._col_name)
                .count()
                .collect()
            )

        def tolist(self) -> list[any]:
            return [row[0] for row in self._data.select(self._col_name).collect()]

        def apply(self, func) -> any:
            pass

        def __len__(self) -> int:
            return self._data.count()

        def __getitem__(self, index: int) -> dict:
            return (
                self._data
                .filter(F.col("_row_id") == index)
                .select(self._col_name)
                .first()[0]
            )

        def __setitem__(self, index: int, value: Any) -> None:
            raise NotImplementedError("Setting items by index is not supported.")

else:
    class PySparkDataSource:
        def __init__(self, *args, **kwargs):
            raise ImportError("PySpark is not installed. Please install with: pip install your-package[pyspark]")


    class PySparkDataColumn:
        def __init__(self, *args, **kwargs):
            raise ImportError("PySpark is not installed. Please install with: pip install your-package[pyspark]")

if __name__ == '__main__':
    tmp = CSVDataSource('corpus/test.csv')
    print(tmp[:10])
    cnt = 0

    for item in tmp:
        cnt += 1
        print(item)
        if cnt == 10:
            break
