# One Stop Anomaly Shop (OSAS)

## Quick start guide

**Step 1:** Get/build the docker image

***Option 1:*** Use precompiled image (might not reflect latest changes):

```shell
docker pull tiberiu44/osas:latest
docker image tag tiberiu44/osas:latest osas:latest
```

***Option 2:*** Build the image locally

```shell
git clone https://github.com/adobe/OSAS.git
cd OSAS
docker build . -f docker/osas-elastic/Dockerfile -t osas:latest
```

**Step 2:** After building the docker image you can start OSAS by typing:

```shell
docker run -p 8888:8888/tcp -p 5601:5601/tcp -v <ABSOLUTE PATH TO DATA FOLDER>:/app osas
```

**IMPORTANT NOTE:** Please modify the above command by adding the absolute path to your datafolder in the appropiate location

After OSAS has started (it might take 1-2 minutes) you can use your browser to access some standard endpoints:
* [http://localhost:5601/app/home#/](http://localhost:5601/app/home#/) - access to Kibana frontend (this is where you will see your data)
* [http://localhost:8888/osas/console](http://localhost:8888/osas/console) - command-line access to osas scripts and utilities

For Debug (in case you need to):

```shell
docker run -p 8888:8888/tcp -p 5601:5601/tcp -v <ABSOLUTE PATH TO DATA FOLDER>:/app -ti osas /bin/bash
```

## Building the test pipeline

This guide will take you through all the necessary steps to configure, train and run your own pipeline on your own dataset.

**Prerequisite**: Add you own CSV dataset into your data-folder (the one provided in the `docker run` command)

Once you have started your docker image, use the [OSAS console](http://localhost:8888/osas/console) to gain CLI access to all the tools.

In what follows, we assume that your dataset is called `dataset.csv`. Please update the commands as necessary in case you use a different name/location.

**Be sure you are running scripts in the root folder of OSAS:**

```bash
cd /osas
```
**Step 1:** Build a custom pipeline configuration file - this can be done fully manually on by bootstraping using our conf autogenerator script:
```bash
python3 osas/main/autoconfig.py --input-file=/app/dataset.csv --output-file=/app/dataset.conf
```

The above command will generate a custom configuration file for your dataset. It will try guess field types and optimal combinations between fields. You can edit the generated file (which should be available in the shared data-folder), using your favourite editor.

Standard templates for label generator types are:

```editorconfig
[LG_MULTINOMIAL]
generator_type = MultinomialField
field_name = <FIELD_NAME>
absolute_threshold = 10
relative_threshold = 0.1

[LG_TEXT]
generator_type = TextField
field_name = <FIELD_NAME>
lm_mode = char
ngram_range = (3, 5)

[LG_NUMERIC]
generator_type = NumericField
field_name = <FIELD_NAME>

[LG_MULTINOMIAL_COMBINER]
generator_type = MultinomialFieldCombiner
field_names = ['<FIELD_1>', '<FIELD_2>', ...]
absolute_threshold = 10
relative_threshold = 0.1

[LG_KEYWORD]
generator_type = KeywordBased
field_name = <FIELD_NAME>
keyword_list = ['<KEYWORD_1>', '<KEYWORD_2>', '<KEYWORD_3>', ...]

[LG_REGEX]
generator_type = KnowledgeBased
field_name = <FIELD_NAME>
rules_and_labels_tuple_list = [('<REGEX_1>','<LABEL_1>'), ('<REGEX_2>','<LABEL_2>'), ...]
```

You can use the above templates to add as many label generators you want. Just make sure that the header IDs are unique in the configuration file.

**Step 2:** Train the pipeline

```bash
python3 osas/main/train_pipeline --conf-file=/app/dataset.conf --input-file=/app/dataset.csv --model-file=/app/dataset.json
```

The above command will generate a pretrained pipeline using the previously created configuration file and the dataset

**Step 3:** Run the pipeline on a dataset 

```bash
python3 osas/main/run_pipeline --conf-file=/app/dataset.conf --model-file=/app/dataset.json --input-file=/app/dataset.csv --output-file=/app/dataset-out.csv
```

The above command will run the pretrained pipeline on any compatible dataset. In the example we run the pipeline on the training data, but you can use previously unseen data. It will generate an output file with labels and anomaly scores and it will also import your data into Elasticsearch/Kibana. To view the result just use the the [web interface](http://localhost:5601/app/dashboards).

# Pipeline explained

The pipeline sequentially applies all label generators on the raw data, collects the labels and uses an anomaly scoring algorithm to generate anomaly scores. 
There are two main component classes: LabelGenerator and ScoringAlgorithm.

## Label generators

**NumericField**

* This type of LabelGenerator handles numerical fields. It computes the mean and standard deviation and generates labels according to
    the distance between the current value and the mean value (value<=sigma NORMAL, sigma<value<=2*sigma BORDERLINE,
    2*sigma<value OUTLIER)

Params:
* ***field_name***: what field to look for in the data object

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
* This type of LabelGenerator handles fields with discreet value sets. It computes the probability of seeing a specific value and alerts based on relative and absolute thresholds.

Params
* ***field_name:*** What field to use
* ***absolute_threshold:*** Minimum absolute value for occurrences to trigger alert for
* ***relative_threshold:*** Minimum relative value for occurrences to trigger alert for

**MultinomialFieldCombiner**
* This type of LabelGenerator handles fields with discreet value sets and build advanced features by combining values across the same dataset entry. It computes the probability of seeing a specific value and alerts based on relative and absolute thresholds.

Params
* ***field_names:*** What fields to combine
* ***absolute_threshold:*** Minimum absolute value for occurrences to trigger alert for
* ***relative_threshold:*** Minimum relative value for occurrences to trigger alert for

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



