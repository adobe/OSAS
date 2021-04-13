#!/bin/sh
mkdir -p /data/elastic/logs
mkdir -p /data/elastic/data
mkdir -p /data/kibana
#/etc/init.d/elasticsearch restart
cd /elasticsearch/
./opendistro-tar-install.sh


cd /osas/scripts/tmp_data



echo "copying data to data"
tar -xvf data.tar.gz  -C /



cp /osas/scripts/config/elasticsearch.yml /elasticsearch/config/
cp /osas/scripts/config/kibana.yml /opendistroforelasticsearch-kibana/config/




chown elasticsearch:elasticsearch /data/elastic -R
chown elasticsearch:elasticsearch /elasticsearch -R




sudo -H -u elasticsearch bash -c 'ES_PATH_CONF=/elasticsearch/config /elasticsearch/bin/elasticsearch &'
DATA_PATH=/data/kibana /opendistroforelasticsearch-kibana/bin/kibana -c /opendistroforelasticsearch-kibana/config/kibana.yml --allow-root &

cd /osas/
export TERM=xterm
python3 osas/webserver.py



#########in prod this should be taken out
#echo "sleep before data push"
#sleep 60
#cd /osas/scripts/tmp_data
#
#python3 json_uploader.py