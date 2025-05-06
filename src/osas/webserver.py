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

from flask import Flask
from flask import Response
from flask import request
from flask import render_template, send_from_directory, send_file
from os import listdir
from os.path import isfile, join
import subprocess
import configparser
import pty
import os
import threading
import shlex
import select
import struct
import termios
import fcntl

if os.path.isdir('/app'):
    data_path='/app/'
else:
    data_path = 'tests/'

app = Flask(__name__)
pty_buffer = []


@app.route('/', defaults={'path': ''})
@app.route('/osas')
def index():
    text = '''<br>OSAS server is running</br>
            <br>For console interaction, go to <a href="/osas/console">http://127.0.0.1:8888/osas/console</a> and follow the steps</br>
            <br>For automated pipeline, go to <a href="/osas/run_full_process">http://127.0.0.1:8888/osas/run_full_process</a></br>
            <br>For custom pipeline, go to <a href="/osas/generate_config">http://127.0.0.1:8888/osas/generate_config</a> and follow the steps</br>
            '''
    return text


@app.route('/osas/static/<path:filename>')
def assets(filename):
    # Add custom handling here.
    # Send a file download response.
    # print(path)
    print(filename)
    return send_file('templates/static/{0}'.format(filename))


@app.route('/osas/console', methods=['GET', 'POST'])
def console_print():
    return render_template("console.html")


@app.route('/osas/console/read', methods=['GET', 'POST'])
def console_read():
    global pty_buffer
    tmp = pty_buffer
    pty_buffer = []

    return ''.join([chr(c) for c in tmp])


@app.route('/osas/console/size', methods=['GET', 'POST'])
def console_size():
    xpix = 0
    ypix = 0

    global pty_fd
    data = request.json
    print(data)
    winsize = struct.pack("HHHH", data['row'], data['col'], xpix, ypix)
    fcntl.ioctl(pty_fd, termios.TIOCSWINSZ, winsize)
    return ''


@app.route('/osas/console/write', methods=['GET', 'POST'])
def console_write():
    data = request.json
    # print(data)
    global pty_fd
    data = data['asciiKey'].encode()
    # print(data)
    os.write(pty_fd, data)

    global pty_buffer
    tmp = pty_buffer
    pty_buffer = []
    # print("returning {0}".format(tmp))
    return ''.join([chr(c) for c in tmp])


pty_fd = None


def pty_read(f):
    global pty_fd
    pty_fd = f

    def rthread(fd):
        while (True):
            import time
            time.sleep(0.02)
            (data_ready, _, _) = select.select([fd], [], [], 0)
            if data_ready:
                global pty_buffer
                data = os.read(fd, 1024 * 1024)
                # print(str(data))
                pty_buffer += data  # data.decode("utf-8")

    x = threading.Thread(target=rthread, args=(f,), daemon=True)
    x.start()


# def pty_start():
#     pty.spawn("bash", pty_read)
#
#
# x = threading.Thread(target=pty_start, args=(), daemon=True)
# x.start()

(child_pid, fd) = pty.fork()
if child_pid == 0:
    # this is the child process fork.
    # anything printed here will show up in the pty, including the output
    # of this subprocess
    subprocess.run("bash")
else:
    # this is the parent process fork.
    # store child fd and pid
    # app.config["fd"] = fd
    # app.config["child_pid"] = child_pid
    # set_winsize(fd, 50, 50)
    pty_fd = fd
    os.write(pty_fd, 'export TERM=xterm\n'.encode())
    cmd = " ".join(shlex.quote(c) for c in "bash")
    print("child pid is", child_pid)
    print(
        f"starting background task with command `{cmd}` to continously read "
        "and forward pty output to client"
    )
    # socketio.start_background_task(target=read_and_forward_pty_output)
    print("task started")
    print(pty_fd)
    pty_read(pty_fd)


@app.route('/osas/generate_config', methods=['GET', 'POST'])
def generate_config():
    print(request.method)
    if request.method == 'GET':
        onlyfiles = [f for f in listdir(data_path) if
                     isfile(join(data_path, f)) and '.conf' not in f and 'pipeline' not in f and '.model' not in f]
        files = onlyfiles

        return render_template("generate_config.html", files=files, len=len(files))

    if request.method == 'POST':
        data = request.form.to_dict()
        # print(data)
        input = data['input']
        output = data['output']
        print(input)
        print(output)
        if '.conf' not in output:
            output += '.conf'

        def inner():
            proc = subprocess.Popen(['python3 osas/main/autoconfig.py --input-file={} --output-file={} 2>&1'.format(
                data_path + input, data_path + output)], shell=True, stdout=subprocess.PIPE)

            for line in iter(proc.stdout.readline, ''):
                try:
                    yield line.rstrip().decode('ascii') + '<br/>\n'
                except:
                    a = None
                poll = proc.poll()
                if poll is not None:
                    yield 'DONE!<br/>\n'
                    full_text = """go to <a href="/osas/confirm_config">http://127.0.0.1:8888/osas/confirm_config</a>
                     <script>
    setTimeout(function(){
        window.location.href = '/osas/confirm_config';
    }, 10000);
</script>"""
                    # yield 'go to <a href="/osas/confirm_config">http://127.0.0.1:8888/osas/confirm_config</a>'
                    yield full_text
                    break

        #
        return Response(inner(), mimetype='text/html')
        # return request.data


@app.route('/osas/confirm_config', methods=['GET', 'POST'])
def confirm_config():
    config = configparser.ConfigParser()
    print(request.method)

    if request.method == 'GET':
        onlyfiles = [f for f in listdir(data_path) if
                     isfile(join(data_path, f)) and '.conf' in f and 'pipeline' not in f]
        files = onlyfiles
        return render_template("config_manual_update.html", files=files, len=len(files))

    if request.method == 'POST':
        print(request.form)
        print('here')
        input = request.form['input']
        try:
            output = request.form['output']
        except:
            output = None
        try:
            text_box = request.form['text_box']
        except:
            text_box = None

        if output == None and text_box == None:
            files = [str(input)]
            config_data = 'data'
            config.read(data_path + input)
            # print(config.sections())
            config_obj = []
            for section in config.sections():
                elem = []
                if section == 'AnomalyScoring':
                    a = 1
                else:

                    elem.append(section)
                    elem.append(config[section]['generator_type'])
                    try:
                        elem.append(config[section]['field_name'])
                    except:
                        elem.append(config[section]['field_names'])

                    config_obj.append(elem)

            # print(config_obj)
            output = "tailored_" + input.replace('.conf', '')
            Anomaly_list = ['StatisticalNGramAnomaly', 'SVDAnomaly', 'LOFAnomaly', 'IFAnomaly', 'SupervisedClassifierAnomaly']
            return render_template("config_manual_update.html", files=files, len=len(files), config=config_data,
                                   input=input, config_obj=config_obj, len_config=len(config_obj),
                                   anomaly_alg=Anomaly_list, output=output)

        elif output != None:
            data = request.form.to_dict()
            output = data['output'] + '.conf'
            data.pop('output')
            input = data['input']
            data.pop('input')
            Anomaly = data['Anomaly']
            data.pop('Anomaly')
            ground_truth_column = data['ground-truth-column']
            data.pop('ground-truth-column')
            classifier = data['classifier']
            data.pop('classifier')
            model_args = data['model-args']
            data.pop('model-args')
            labels = list(data.keys())
            print(labels)

            config.read(data_path + input)
            new_config = configparser.ConfigParser()
            for label in labels:
                print(config[label])
                new_config[label] = config[label]
            new_config['AnomalyScoring'] = config['AnomalyScoring']
            new_config['AnomalyScoring']['scoring_algorithm'] = Anomaly
            if Anomaly == 'SupervisedClassifierAnomaly':
                new_config['AnomalyScoring']['ground_truth_column'] = ground_truth_column
                new_config['AnomalyScoring']['classifier'] = classifier
                model_args = model_args.split('\n')
                for model_arg in model_args:
                    model_arg = model_arg.split('=')
                    new_config['AnomalyScoring'][model_arg[0].strip()] = model_arg[1].strip()
            with open(data_path + output, 'w') as configfile:
                new_config.write(configfile)
            input_data = open('osas/templates/config_static.txt', 'r').read() + "\n\n" + open(data_path + output,
                                                                                              'r').read()
            print(output)
            # print(input_data)
            return render_template("config_text_edit.html", input=[output], input_data=input_data)

        elif output == None and text_box != None:
            data = request.form.to_dict()
            input = data['input']
            text_box = data['text_box']

            with open(data_path + input, 'w') as configfile:
                configfile.write(text_box)
            return '<script>document.location.href="http://127.0.01:8888/osas/train_pipeline"</script>'


@app.route('/osas/train_pipeline', methods=['GET', 'POST'])
def train_pipeline():
    print(request.method)
    if request.method == 'GET':
        onlyfiles = [f for f in listdir(data_path) if isfile(join(data_path, f)) and '.conf' in f and '.model' not in f]
        files = onlyfiles

        onlyfiles_dataset = [f for f in listdir(data_path) if
                             isfile(join(data_path, f)) and '.conf' not in f and '.model' not in f]
        dataset = onlyfiles_dataset

        return render_template("train_pipeline.html", files=files, len=len(files), dataset=dataset,
                               len_dataset=len(dataset))

    if request.method == 'POST':
        input = request.form['input']
        input_conf = request.form['input_conf']

        output = request.form['output']
        print(input)
        print(output)
        if '.model' not in output:
            output += '.model'

        def inner():
            proc = subprocess.Popen([
                'python3 osas/main/train_pipeline.py --input-file={} --conf-file={} --model-file={} 2>&1'.format(
                    data_path + input, data_path + input_conf, data_path + output)], shell=True,
                stdout=subprocess.PIPE)

            for line in iter(proc.stdout.readline, ''):
                try:
                    yield line.rstrip().decode('ascii') + '<br/>\n'
                except:
                    a = None
                poll = proc.poll()
                if poll is not None:
                    yield 'DONE!<br/>\n'
                    # yield 'go to <a href="/osas/run_pipeline">http://127.0.0.1:8888/osas/run_pipeline</a>'
                    full_text = """go to <a href="/osas/run_pipeline">http://127.0.0.1:8888/osas/run_pipeline</a>
                        <script>
                    setTimeout(function(){
                        window.location.href = '/osas/run_pipeline';
                    }, 10000);
                        </script>"""
                    yield full_text
                    break

        #
        return Response(inner(), mimetype='text/html')


@app.route('/osas/run_pipeline', methods=['GET', 'POST'])
def run_pipeline():
    print(request.method)
    if request.method == 'GET':
        onlyfiles = [f for f in listdir(data_path) if
                     isfile(join(data_path, f)) and '.conf' in f and 'pipeline' not in f]
        files = onlyfiles

        onlyfiles_dataset = [f for f in listdir(data_path) if
                             isfile(join(data_path, f)) and '.conf' not in f and '.model' not in f]
        dataset = onlyfiles_dataset

        onlyfiles_dataset = [f for f in listdir(data_path) if isfile(join(data_path, f)) and '.model' in f]
        pipeline = onlyfiles_dataset

        return render_template("run_pipeline.html", files=files, len=len(files), dataset=dataset,
                               len_dataset=len(dataset), pipeline=pipeline, len_pipeline=len(pipeline))

    if request.method == 'POST':
        input = request.form['input']
        input_conf = request.form['input_conf']
        model_conf = request.form['model_conf']

        output = request.form['output']
        print(input)
        print(output)
        if '.csv' not in output:
            output += '.csv'

        def inner():
            proc = subprocess.Popen([
                'python3 osas/main/run_pipeline.py --input-file={} --conf-file={} --model-file={} --output-file={} 2>&1'.format(
                    data_path + input, data_path + input_conf, data_path + model_conf,
                    data_path + output)], shell=True, stdout=subprocess.PIPE)

            for line in iter(proc.stdout.readline, ''):
                try:
                    yield line.rstrip().decode('ascii') + '<br/>\n'
                except:
                    a = None
                poll = proc.poll()
                if poll is not None:
                    yield 'DONE!<br/>\n'
                    # yield 'go to kibana http://127.0.0.1:5601'
                    full_text = """go to http://127.0.0.1:5601</a>
                        <script>
                    setTimeout(function(){
                        window.location.href = 'http://127.0.0.1:5601';
                    }, 30000);
                        </script>"""
                    yield full_text

                    break

        #
        return Response(inner(), mimetype='text/html')


@app.route('/osas/run_full_process', methods=['GET', 'POST'])
def run_full_process():
    print(request.method)
    if request.method == 'GET':
        onlyfiles = [f for f in listdir(data_path) if
                     isfile(join(data_path, f)) and '.conf' not in f and '.model' not in f]
        files = onlyfiles

        return render_template("run_full_process.html", files=files, len=len(files))

    if request.method == 'POST':
        input = request.form['input']
        output = request.form['output']
        print(input)
        print(output)
        if '.csv' not in output:
            output += '.csv'

        def inner():
            import datetime
            stamp = str(datetime.datetime.now())[0:19].replace(' ', '_').replace(':', '_')
            key = input.split('.')[0] + "_" + stamp
            commands = []
            commands.append(
                'python3 osas/main/autoconfig.py --input-file={} --output-file={}.conf 2>&1'.format(data_path + input,
                                                                                                 data_path + key))
            commands.append(
                'python3 osas/main/train_pipeline.py --input-file={} --conf-file={}.conf --model-file={}.model 2>&1'.format(
                    data_path + input, data_path + key, data_path + key))
            commands.append(
                'python3 osas/main/run_pipeline.py --input-file={} --conf-file={}.conf --model-file={}.model --output-file={} 2>&1'.format(
                    data_path + input, data_path + key, data_path + key, data_path + output))

            for command in commands:
                yield command + '<br/>\n' + '<br/>\n'
                proc = subprocess.Popen([command], shell=True, stdout=subprocess.PIPE)

                for line in iter(proc.stdout.readline, ''):

                    try:
                        yield line.rstrip().decode('ascii') + '<br/>\n'
                    except:
                        a = None
                    poll = proc.poll()
                    if poll is not None:
                        yield 'DONE!<br/>\n'
                        yield 'NEXT:<br/>\n'
                        break
            yield 'go to kibana http://127.0.0.1:5601'

        #
        return Response(inner(), mimetype='text/html')


app.run(port=8888, host='0.0.0.0', debug=True)
