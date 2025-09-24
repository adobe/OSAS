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

from typing import Dict, Any, List
from osas.core.interfaces import Datasource


class MockDatasource(Datasource):
    """Simple mock datasource for testing"""
    
    def __init__(self, data: List[Dict[str, Any]]):
        self._data = data
    
    def __len__(self) -> int:
        return len(self._data)
    
    def __getitem__(self, index: int) -> dict:
        return self._data[index]
    
    def __setitem__(self, key: str, value: Any):
        # Not needed for these tests
        pass
    
    def apply(self, func, axis: int = 0) -> List[Any]:
        """Apply function to each row"""
        return [func(item) for item in self._data]
    
    def save(self, file_handle) -> None:
        # Not needed for these tests
        pass
    
    def groupby(self, column_name: str, agg_func):
        # Not needed for these tests
        pass
