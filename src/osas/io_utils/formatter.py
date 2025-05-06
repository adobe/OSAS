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

# object type conversion/formatting utility functions
import ast
import json
import sys


def eval_str(x):
    try:
        return ast.literal_eval(x)
    except Exception as e:
        fstr = 'osas/io_utils/formatter.py:eval_str()'
        print("[{}]Error--{}".format(fstr, e), file=sys.stderr)


def dict_to_str(d):
    try:
        return json.dumps(d)
    except Exception as e:
        fstr = 'osas/io_utils/formatter.py:dict_to_str()'
        print("[{}]Error--{}".format(fstr, e), file=sys.stderr)


def str_to_dict(s):
    try:
        return json.loads(s)
    except Exception as e:
        fstr = 'osas/io_utils/formatter.py:str_to_dict()'
        print("[{}]Error--{}".format(fstr, e), file=sys.stderr)
