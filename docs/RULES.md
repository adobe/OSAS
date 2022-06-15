# Rule-based labeling and anomaly scoring

Once you have a working pipeline, you might want to refine your results by adding some human-expert knowledge on the dataset and generated labels. Using the static rules you can:

* Add new labels to your dataset: for instance you want to highlight when a special user (say `system@mydatabase.com`) seems to connect from non-standard countries;
* Change the anomaly score by a relative value, based on specific attribute or label(generated) values (for example, add 100 to the anomaly score when the above happens).

For this, we provide another CLI tool (`osas/main/apply_rules.py`) that takes as input the previously labeled dataset and a folder that contains the static rules, while outputting the modified labels and anomaly scores into a new file:

```bash
python osas/main/apply_rules.py --help
Usage: apply_rules.py [options]

Options:
  -h, --help            show this help message and exit
  --input-file=INPUT_FILE
                        location of the input file
  --rules-folder=RULES_FOLDER
                        location of rules
  --output-file=OUTPUT_FILE
                        output-file (optional)
  --no-elastic          don't push data to Elastic
  ```

**Parameters**
* `--input-file`: path to a CSV file, **already processed** by `run_pipeline.py` 
* `--rules-folder`: path to a system folder containing the static rules in `.yaml` format
* `--output-file`: where to store the results
* `--no-elastic`: don't push data back to elastic (useful when OSAS is run outside the distributed Docker image)

**Note:** OSAS will apply all the rules inside the folder.

## The format of rule files

If you are an impatient reader, you can skip this section and go straight to the example. Everything inside the rule files is self-explanatory and the practical example will probably clarify everything else.

Rules are stored in `YAML` format and must saved in files that have the `.yaml` extension. 
Each rule must contain the following mandatory attributes:

* `rule name`: each rule must have a name (not necessarily unique)
* `rule label`: what label you want to add if this specific rule is a match for one of the examples in your dataset
* `rule score`: this is a floating point value, that will modify the original anomaly scoring. 
* `conditions`: this should indicate a list of conditions that will be the trigger for this rule. The boolean operation between them is `OR`

Each condition has a free-form `label` (key) that is not used anywhere else, except for making the file readable to those who edit it. Then it is followed by a list of attribute names (columns in the CSV) with their possible value/values. The logical operation between attribute matches is `AND` and the logical operator between values is `OR`
Also, the attribute values are regular expression, to allow for wild-cards.

## Example

Say you have a dataset that contains user logins with origin country, ip address (`host`) and timestamp. Also, your infrastructure has some automation that works by connecting to the server from a host with a known IP address (`10.10.10.10`) and user (`privileged@system`).
Additionally, you used the Knowledge based label generator to create a special label to reflect the time of day: `EARLY_MORNING`, `EVENING`, `NIGHT`, and you know that the automation should only run at night.

This is how a rule would look like:

```yaml
rule name: privileged login from unknown ip or outside normal hours
rule label: DANGER_FOR_AUTOMATION_ACCOUNT
rule score: +500
conditions:
  privileged_unkown_ip:
    host: ^((?!10.10.10.10).)*$
    username: privileged@system
  automation_outside_normal_hours:
    labels:
      - EARLY_MORNING
      - EVENING
    username: privileged@system
```

Short explanation:
1. The rule name is `privileged login from unknown ip or outside normal hours`, indicating clearly what it does;
2. The label `DANGER_FOR_AUTOMATION_ACCOUNT` will get added to every example that matches this rule;
3. Every time the rule is matched, the anomaly score will get increased by 500;
4. The rule has two conditions that can be matched independently: `privileged_unkown_ip` and `automation_outside_normal_hours`. If either one of these conditions match, the rule will get executed;
5. Rule 1 (`privileged_unkown_ip`) - looks at the username and expects it to be `privileged@system`. Also, it wants the `host` value to be anything else than `10.10.10.10`
6. Rule 2 (`automation_outside_normal_hours`) - also looks at the username and expects it to be `privileged@system`. Additionally, it checks the labels for any of the two values specified in the list: `EARLY_MORNING` and `EVENING`

We hope that this explains the way rules are applied and how you can build the boolean login around them.

## Tips and tricks

**Tip 1:** The `rule score`, is a modifier that can be positive or negative. Use positive values to highlight alerts, negative values to whitelist events and 0 if you just want the rule-label added;

**Tip 2:** If the attribute name is `labels` than the condition will apply on the labels that OSAS added in the `run_pipeline.py` step;


