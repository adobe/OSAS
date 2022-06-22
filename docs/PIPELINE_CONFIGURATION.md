# Pipeline explained

The pipeline sequentially applies all label generators on the raw data, collects the labels and uses an anomaly scoring algorithm to generate anomaly scores. 
There are two main component classes: LabelGenerator and ScoringAlgorithm.

## Label generators

**NumericField**

* This type of LabelGenerator handles numerical fields. It can compute in two different ways: (1) the mean and standard deviation and generates labels
    according to the distance between the current value and the mean value (value<=sigma NORMAL, sigma<value<=2*sigma BORDERLINE,
    2*sigma<value OUTLIER) and (2) a spike, which can be either a percentage or fixed amount increase/decrease from the mean and generates labels
    if the event is above/below the spike amount. The numeric field must use either one or both of these calculations to generate labels. If both
    stdev and spike are used, it will only generate labels if an event is a spike from the stdev and not from the mean.

Params:
* ***field_name***: what field to look for in the data object
* ***group_by***: when this field is set (not None), statistics are built around the groups obtained using the values of the specified attribute names. For instance, you can use this to compute CPU usage anomalies based on the `station_name` or `cloud_account_id`
* ***label_for_normal***: True/False - when set, it will output labels for normal events. Default `True`
* ***stdev***: True/False - when set, it will use stdev as a calculation method. Default `True`.
* ***stdev_borderline_threshold***: How many standard deviations for an event to be considered borderline. Default `1`.
* ***stdev_outlier_threshold***: How many standard deviations for an event to be considered an outlier. Default `2`.
* ***spike***: none/ratio/fixed - when set (not none), will use ratio or fixed spike calculation. Default `none`.
* ***spike_inverse***: True/False - when set, will caculate spike as a large decrease from the mean. Default `False`.
* ***spike_borderline_threshold***: How much ratio/fixed amount for an event to be considered borderline. If ratio, a value of 2 is 2x above the mean. If fixed, a value of 10 is 10 above the mean. Default `10`.
* ***spike_outlier_threshold***: How much ratio/fixed amount for an event to be considered an outlier. Default `20`.

**TextField**

* This type of LabelGenerator handles text fields. It builds a n-gram based language model and computes the
    perplexity of newly observed data. It also holds statistics over the training data (mean and stdev).
    (perplexity<=sigma NORMAL, sigma<preplexity<=2*sigma BORDERLINE,
    2*perplexity<value OUTLIER)

Params:

* ***field_name:*** What field to look for
* ***lm_mode:*** Type of LM to build: char or token
* ***ngram_range:*** N-gram range to use for computation

**MultinomialField**
* This type of LabelGenerator handles fields with discreet value sets. It computes the probability of seeing a specific value and alerts based on relative and absolute thresholds. If `group_by` is specified, this label generator will compute statistics for target values by first creating buckets.

Params
* ***field_name:*** What field to use
* ***absolute_threshold:*** Minimum absolute value for occurrences to trigger alert for
* ***relative_threshold:*** Minimum relative value for occurrences to trigger alert for
* ***group_by***: when this field is set (not None), statistics are built around the groups obtained using the values of the specified attribute names. For instance, you can use this to compute anomalies for `country_name` login based on the `username`

**MultinomialFieldCombiner**
* This type of LabelGenerator handles fields with discreet value sets and build advanced features by combining values across the same dataset entry. It computes the probability of seeing a specific value and alerts based on relative and absolute thresholds.  If `group_by` is specified, this label generator will compute statistics for target values by first creating buckets.

Params
* ***field_names:*** What fields to combine
* ***absolute_threshold:*** Minimum absolute value for occurrences to trigger alert for
* ***relative_threshold:*** Minimum relative value for occurrences to trigger alert for
* ***group_by***: when this field is set (not None), statistics are built around the groups obtained using the values of the specified attribute names. The same explanation as the one above applies here

**KeywordBased**
* This is a rule-based label generators. It applies a simple tokenization procedure on input text, by dropping special characters and numbers and splitting on white-space. It then looks for a specific set of keywords and generates labels accordingly

Params:
* ***field_name:*** What field to use
* ***keyword_list:*** The list of keywords to look for

OSAS has four unsupervised anomaly detection algorithms:

* **IFAnomaly**: n-hot encoding, singular value decomposition, isolation forest (IF)

* **LOFAnomaly**: n-hot encoding, singular value decomposition, local outlier factor (LOF)

* **SVDAnomaly**: n-hot encoding, singular value decomposition, inverted transform, input reconstruction error

* **StatisticalNGramAnomaly**: compute label n-gram probabilities, compute anomaly score as a sum of negative log likelihood

## Supervised Classifiers

OSAS now has support for supervised classifiers! You can use this if you have a dataset where the anomalies are already labeled for you. You may ask, why would we still use OSAS for an already labeled dataset instead of just running our own model? That's because you can leverage the OSAS label generators we have for your ML features!

Here is an example in a conf file of using the supervised classifier:
```
[AnomalyScoring]
scoring_algorithm = SupervisedClassifierAnomaly
ground_truth_column = status
classifier = sklearn.ensemble.RandomForestClassifier
n_estimators = 100
random_state = 42
```
* `scoring_algorithm` must have `SupervisedClassifierAnomaly`.
* `ground_truth_column` is the column in your input .csv file that is the column of your ground truth labels for the supervised task.
* `classifier` is the supervised classifier class you will use. For now, we are only supporting sklearn models and you must provide the full package path of the sklearn model (ex. `sklearn.ensemble.RandomForestClassifier`). NOTE: The sklearn model will only work if there is a `fit` and `predict_proba` function. So, an sklearn model that is a classifier that returns probabilities.
* The rest of the attributes will be passed in to the `classifier`'s constructor when initialized. In this example, `n_estimators` and `random_state` are constructor arguments for the `RandomForestClassifier`.

For the `ground_truth_column` in your .csv file, there are certain formats we accept that will affect the output of OSAS. For binary classification tasks, you may label your ground truth labels as either `clean`/`bad` or `0`/`1`, `1` being a `bad` label. If you use one of these two naming conventions, the output scores will be returned as a probability score of the input being `bad` (eg. between 0 and 1). For any other naming convention (for both binary and multi-class classification), the output scores will be returned as the predicted labeled rather than a score. For example, if your ground truth labels are `clean`, `unknown`, or `malicious`, then the scores will be returned as either `clean`, `unknown`, or `maclious` rather than the probability of one of these classes.
