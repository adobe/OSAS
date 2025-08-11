"""
Unit tests for MultinomialFieldCombiner class.

Tests basic functionality and merge operation of the MultinomialFieldCombiner
which handles fields with discrete value sets and builds advanced features
by combining values across the same dataset entry.
"""

import unittest
import json
from collections import Counter, defaultdict
from typing import Dict, Any, List

from osas.core.label_generators import MultinomialFieldCombiner
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


class TestMultinomialFieldCombiner(unittest.TestCase):
    """Test cases for MultinomialFieldCombiner functionality"""
    
    def setUp(self):
        """Set up test fixtures"""
        self.test_data = [
            {'user': 'alice', 'action': 'login', 'host': 'server1'},
            {'user': 'alice', 'action': 'login', 'host': 'server1'},
            {'user': 'alice', 'action': 'logout', 'host': 'server1'},
            {'user': 'bob', 'action': 'login', 'host': 'server2'},
            {'user': 'bob', 'action': 'login', 'host': 'server2'},
            {'user': 'charlie', 'action': 'admin', 'host': 'server1'},
        ]
        self.mock_dataset = MockDatasource(self.test_data)
    
    def test_build_model_without_groupby(self):
        """Test building model without group_by parameter"""
        mfc = MultinomialFieldCombiner(['user', 'action'])
        model = mfc.build_model(self.mock_dataset)
        
        # Check that model was built
        self.assertIn('pair2count', model)
        self.assertIn('pair2prob', model)
        
        # Check specific counts
        pair2count = model['pair2count']
        self.assertEqual(pair2count['(alice,login)'], 2)
        self.assertEqual(pair2count['(alice,logout)'], 1)
        self.assertEqual(pair2count['(bob,login)'], 2)
        self.assertEqual(pair2count['(charlie,admin)'], 1)
        self.assertEqual(pair2count['TOTAL'], 6)
        
        # Check specific probabilities
        pair2prob = model['pair2prob']
        self.assertAlmostEqual(pair2prob['(alice,login)'], 2/6, places=3)  # 2 out of 6 total
        self.assertAlmostEqual(pair2prob['(alice,logout)'], 1/6, places=3)  # 1 out of 6 total
        self.assertAlmostEqual(pair2prob['(bob,login)'], 2/6, places=3)  # 2 out of 6 total
        self.assertAlmostEqual(pair2prob['(charlie,admin)'], 1/6, places=3)  # 1 out of 6 total
        self.assertAlmostEqual(pair2prob['TOTAL'], 1.0, places=3)  # TOTAL should be 1.0
    
    def test_build_model_with_groupby(self):
        """Test building model with group_by parameter"""
        mfc = MultinomialFieldCombiner(['user', 'action'], group_by='host')
        model = mfc.build_model(self.mock_dataset)
        
        # Check grouped structure
        pair2count = model['pair2count']
        pair2prob = model['pair2prob']
        self.assertIn('server1', pair2count)
        self.assertIn('server2', pair2count)
        self.assertIn('server1', pair2prob)
        self.assertIn('server2', pair2prob)
        
        # Check server1 group counts
        self.assertEqual(pair2count['server1']['(alice,login)'], 2)
        self.assertEqual(pair2count['server1']['(alice,logout)'], 1)
        self.assertEqual(pair2count['server1']['(charlie,admin)'], 1)
        self.assertEqual(pair2count['server1']['TOTAL'], 4)
        
        # Check server1 group probabilities
        self.assertAlmostEqual(pair2prob['server1']['(alice,login)'], 2/4, places=3)  # 2 out of 4 in server1
        self.assertAlmostEqual(pair2prob['server1']['(alice,logout)'], 1/4, places=3)  # 1 out of 4 in server1
        self.assertAlmostEqual(pair2prob['server1']['(charlie,admin)'], 1/4, places=3)  # 1 out of 4 in server1
        self.assertAlmostEqual(pair2prob['server1']['TOTAL'], 1.0, places=3)  # TOTAL should be 1.0
        
        # Check server2 group counts
        self.assertEqual(pair2count['server2']['(bob,login)'], 2)
        self.assertEqual(pair2count['server2']['TOTAL'], 2)
        
        # Check server2 group probabilities
        self.assertAlmostEqual(pair2prob['server2']['(bob,login)'], 2/2, places=3)  # 2 out of 2 in server2
        self.assertAlmostEqual(pair2prob['server2']['TOTAL'], 1.0, places=3)  # TOTAL should be 1.0
    
    def test_call_method_without_groupby(self):
        """Test the __call__ method without group_by"""
        mfc = MultinomialFieldCombiner(['user', 'action'], absolute_threshold=2, relative_threshold=0.25)
        mfc.build_model(self.mock_dataset)
        
        # Test seen combination with sufficient count and probability
        labels = mfc({'user': 'alice', 'action': 'login'})
        self.assertEqual(labels, [])  # Should not trigger any alerts
        
        # Test seen combination with low count
        labels = mfc({'user': 'charlie', 'action': 'admin'})
        self.assertIn('LOW_OBS_COUNT_FOR_USER_ACTION_PAIR', labels)
        
        # Test unseen combination
        labels = mfc({'user': 'dave', 'action': 'delete'})
        self.assertEqual(labels, ['UNSEEN_USER_ACTION_PAIR'])
    
    def test_call_method_with_groupby(self):
        """Test the __call__ method with group_by"""
        mfc = MultinomialFieldCombiner(['user', 'action'], group_by='host', absolute_threshold=2, relative_threshold=0.4)
        mfc.build_model(self.mock_dataset)
        
        # Test seen combination in existing group
        labels = mfc({'user': 'alice', 'action': 'login', 'host': 'server1'})
        self.assertEqual(labels, [])  # Should not trigger alerts
        
        # Test seen combination with low count in group
        labels = mfc({'user': 'charlie', 'action': 'admin', 'host': 'server1'})
        self.assertIn('LOW_OBS_COUNT_FOR_USER_ACTION_PAIR_BASED_ON_HOST', labels)
        
        # Test combination in unseen group
        labels = mfc({'user': 'alice', 'action': 'login', 'host': 'server3'})
        self.assertEqual(labels, [])  # Empty for unseen group
    
    def test_merge_functionality_without_groupby(self):
        """Test merge functionality without group_by"""
        # Create first combiner with some data
        mfc1 = MultinomialFieldCombiner(['user', 'action'])
        data1 = [
            {'user': 'alice', 'action': 'login'},
            {'user': 'alice', 'action': 'login'},
            {'user': 'bob', 'action': 'logout'}
        ]
        mfc1.build_model(MockDatasource(data1))
        
        # Create second combiner with different data
        mfc2 = MultinomialFieldCombiner(['user', 'action'])
        data2 = [
            {'user': 'alice', 'action': 'login'},
            {'user': 'charlie', 'action': 'admin'}
        ]
        mfc2.build_model(MockDatasource(data2))
        
        # Merge the second into the first
        mfc1.merge([mfc2])
        
        # Check merged counts
        pair2count = mfc1._model['pair2count']
        self.assertEqual(pair2count['(alice,login)'], 3)  # 2 + 1
        self.assertEqual(pair2count['(bob,logout)'], 1)
        self.assertEqual(pair2count['(charlie,admin)'], 1)
        self.assertEqual(pair2count['TOTAL'], 5)  # 3 + 2
        
        # Check that grand_total was updated
        self.assertEqual(mfc1._model['grand_total'], 5)
        
        # Check that probabilities were recalculated correctly after merge
        pair2prob = mfc1._model['pair2prob']
        self.assertAlmostEqual(pair2prob['(alice,login)'], 3/5, places=3)  # 3 out of 5 total
        self.assertAlmostEqual(pair2prob['(bob,logout)'], 1/5, places=3)  # 1 out of 5 total
        self.assertAlmostEqual(pair2prob['(charlie,admin)'], 1/5, places=3)  # 1 out of 5 total
    
    def test_merge_functionality_with_groupby(self):
        """Test merge functionality with group_by"""
        # Create first combiner with grouped data
        mfc1 = MultinomialFieldCombiner(['user', 'action'], group_by='host')
        data1 = [
            {'user': 'alice', 'action': 'login', 'host': 'server1'},
            {'user': 'alice', 'action': 'login', 'host': 'server1'},
            {'user': 'bob', 'action': 'logout', 'host': 'server2'}
        ]
        mfc1.build_model(MockDatasource(data1))
        
        # Create second combiner with overlapping groups
        mfc2 = MultinomialFieldCombiner(['user', 'action'], group_by='host')
        data2 = [
            {'user': 'alice', 'action': 'login', 'host': 'server1'},
            {'user': 'charlie', 'action': 'admin', 'host': 'server3'}
        ]
        mfc2.build_model(MockDatasource(data2))
        
        # Merge the second into the first
        mfc1.merge([mfc2])
        
        # Check merged counts
        pair2count = mfc1._model['pair2count']
        
        # Check server1 group (should be merged)
        self.assertEqual(pair2count['server1']['(alice,login)'], 3)  # 2 + 1
        self.assertEqual(pair2count['server1']['TOTAL'], 3)  # 2 + 1
        
        # Check server2 group (unchanged)
        self.assertEqual(pair2count['server2']['(bob,logout)'], 1)
        self.assertEqual(pair2count['server2']['TOTAL'], 1)
        
        # Check server3 group (new)
        self.assertEqual(pair2count['server3']['(charlie,admin)'], 1)
        self.assertEqual(pair2count['server3']['TOTAL'], 1)
        
        # Check that probabilities were recalculated correctly after merge
        pair2prob = mfc1._model['pair2prob']
        
        # Server1 probabilities after merge
        self.assertAlmostEqual(pair2prob['server1']['(alice,login)'], 3/3, places=3)  # 3 out of 3 in server1
        self.assertAlmostEqual(pair2prob['server1']['TOTAL'], 1.0, places=3)
        
        # Server2 probabilities (unchanged)
        self.assertAlmostEqual(pair2prob['server2']['(bob,logout)'], 1/1, places=3)  # 1 out of 1 in server2
        self.assertAlmostEqual(pair2prob['server2']['TOTAL'], 1.0, places=3)
        
        # Server3 probabilities (new)
        self.assertAlmostEqual(pair2prob['server3']['(charlie,admin)'], 1/1, places=3)  # 1 out of 1 in server3
        self.assertAlmostEqual(pair2prob['server3']['TOTAL'], 1.0, places=3)
    
    def test_merge_incompatible_generators(self):
        """Test merge with incompatible generators raises error"""
        mfc1 = MultinomialFieldCombiner(['user', 'action'])
        mfc2 = MultinomialFieldCombiner(['user', 'host'])  # Different field names
        
        mfc1.build_model(MockDatasource(self.test_data[:2]))
        mfc2.build_model(MockDatasource(self.test_data[:2]))
        
        with self.assertRaises(ValueError):
            mfc1.merge([mfc2])
    
    def test_from_pretrained(self):
        """Test loading from pretrained model"""
        mfc = MultinomialFieldCombiner(['user', 'action'])
        mfc.build_model(self.mock_dataset)
        
        # Serialize the model
        model_json = json.dumps(mfc._model)
        
        # Load from pretrained
        mfc_loaded = MultinomialFieldCombiner.from_pretrained(model_json)
        
        # Check that the models are equivalent
        self.assertEqual(mfc._model['field_names'], mfc_loaded._model['field_names'])
        self.assertEqual(mfc._model['pair2count'], mfc_loaded._model['pair2count'])
        self.assertEqual(mfc._model['absolute_threshold'], mfc_loaded._model['absolute_threshold'])
        self.assertEqual(mfc._model['relative_threshold'], mfc_loaded._model['relative_threshold'])
    
    def test_with_count_column(self):
        """Test building model with count column"""
        data_with_counts = [
            {'user': 'alice', 'action': 'login', 'count': 5},
            {'user': 'bob', 'action': 'logout', 'count': 3},
            {'user': 'alice', 'action': 'login', 'count': 2}
        ]
        
        mfc = MultinomialFieldCombiner(['user', 'action'])
        model = mfc.build_model(MockDatasource(data_with_counts), count_column='count')
        
        # Check that counts were properly aggregated
        pair2count = model['pair2count']
        self.assertEqual(pair2count['(alice,login)'], 7)  # 5 + 2
        self.assertEqual(pair2count['(bob,logout)'], 3)
        self.assertEqual(pair2count['TOTAL'], 10)  # 5 + 3 + 2
        
        # Check that probabilities were calculated correctly with count column
        pair2prob = model['pair2prob']
        self.assertAlmostEqual(pair2prob['(alice,login)'], 7/10, places=3)  # 7 out of 10 total
        self.assertAlmostEqual(pair2prob['(bob,logout)'], 3/10, places=3)  # 3 out of 10 total
        self.assertAlmostEqual(pair2prob['TOTAL'], 1.0, places=3)  # TOTAL should be 1.0


if __name__ == '__main__':
    unittest.main()
