# One Stop Anomaly Shop (OSAS)

This repository implements the models, methods and techniques presented in our paper: [A Principled Approach to Enriching Security-related Data for Running Processes through Statistics and Natural Language Processing](https://www.scitepress.org/Papers/2021/103814/103814.pdf).

## Introduction video (follows quick start guide)

This video is a recording of our Hack In The Box (HITB) Security Conference 2021 Amsterdam presentation.

[![IMAGE ALT TEXT HERE](https://img.youtube.com/vi/Wi5NXGzsFC4/0.jpg)](https://www.youtube.com/watch?v=Wi5NXGzsFC4)]

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
* [http://localhost:8888/?token=osas](http://localhost:8888/?token=osas) - access to Jupyter Lab (open Terminal or create a Notebook)

For Debug (in case you need to):

```shell
docker run -p 8888:8888/tcp -p 5601:5601/tcp -v <ABSOLUTE PATH TO DATA FOLDER>:/app -ti osas /bin/bash
```

## Building the test pipeline

This guide will take you through all the necessary steps to configure, train and run your own pipeline on your own dataset.

**Prerequisite**: Add you own CSV dataset into your data-folder (the one provided in the `docker run` command)

Once you started your docker image, use the [OSAS console](http://localhost:8888/osas/console) to gain CLI access to all the tools.

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
group_by = None # this is an optional field - it can be a single attribute name or a list of names

[LG_TEXT]
generator_type = TextField
field_name = <FIELD_NAME>
lm_mode = char
ngram_range = (3, 5)

[LG_NUMERIC]
generator_type = NumericField
field_name = <FIELD_NAME>
group_by = None # this is an optional field - it can be a single attribute name or a list of names

[LG_MUTLINOMIAL_COMBINER]
generator_type = MultinomialFieldCombiner
field_names = ['<FIELD_1>', '<FIELD_2>', ...]
absolute_threshold = 10
relative_threshold = 0.1
group_by = None # this is an optional field - it can be a single attribute name or a list of names

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
python3 osas/main/train_pipeline.py --conf-file=/app/dataset.conf --input-file=/app/dataset.csv --model-file=/app/dataset.json
```

The above command will generate a pretrained pipeline using the previously created configuration file and the dataset

**Step 3:** Run the pipeline on a dataset 

```bash
python3 osas/main/run_pipeline.py --conf-file=/app/dataset.conf --model-file=/app/dataset.json --input-file=/app/dataset.csv --output-file=/app/dataset-out.csv
```

The above command will run the pretrained pipeline on any compatible dataset. In the example we run the pipeline on the training data, but you can use previously unseen data. It will generate an output file with labels and anomaly scores and it will also import your data into Elasticsearch/Kibana. To view the result just use the the [web interface](http://localhost:5601/app/dashboards).

# Developing models

Now that everything is up and running, we prepared a set of development guidelines that will help you apply OSAS on your own dataset:

1. [Pipeline configuration](docs/PIPELINE_CONFIGURATION.md): This will help you understand how the label generators and anomaly scoring works in OSAS;
2. [Rule-based score modifiers and labeling](docs/RULES.md): Once you have a working OSAS pipeline, you can furhter refine your results by adding new labels and modifying the anomaly scoring based on static rules.

# Citing and attribution

**Full-text-paper: [A Principled Approach to Enriching Security-related Data for Running Processes through Statistics and Natural Language Processing](https://www.scitepress.org/Papers/2021/103814/103814.pdf).**

If you want to use this repository in any academic work, please cite the following work:

**MLA**
  * Boros, Tiberiu, et al. ‘A Principled Approach to Enriching Security-Related Data for Running Processes through Statistics and Natural Language Processing’. IoTBDS 2021 - 6th International Conference on Internet of Things, Big Data and Security, 2021.

**APA**
  * Boros, T., Cotaie, A., Vikramjeet, K., Malik, V., Park, L., & Pachis, N. (2021). A principled approach to enriching security-related data for running processes through statistics and natural language processing. IoTBDS 2021 - 6th International Conference on Internet of Things, Big Data and Security. 

**Chicago**
  * Boros, Tiberiu, Andrei Cotaie, Kumar Vikramjeet, Vivek Malik, Lauren Park, and Nick Pachis. ‘A Principled Approach to Enriching Security-Related Data for Running Processes through Statistics and Natural Language Processing’. In IoTBDS 2021 - 6th International Conference on Internet of Things, Big Data and Security, 2021.
    
**BibTeX**

```text
@article{boros2021principled,
  title={A Principled Approach to Enriching Security-related Data for Running Processes through Statistics and Natural Language Processing},
  author={Boros, Tiberiu and Cotaie, Andrei and Vikramjeet, Kumar and Malik, Vivek and Park, Lauren and Pachis, Nick},
  year={2021},
  booktitle={IoTBDS 2021 - 6th International Conference on Internet of Things, Big Data and Security}
}
```