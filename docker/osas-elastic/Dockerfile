FROM debian
ENV APT_KEY_DONT_WARN_ON_DANGEROUS_USAGE=1
RUN apt update && apt install -y gnupg2 curl procps openjdk-11-jdk unzip wget dbus sudo

RUN wget -qO - https://d3g5vo6xdbdb9a.cloudfront.net/GPG-KEY-opendistroforelasticsearch | apt-key add -
RUN echo "deb https://d3g5vo6xdbdb9a.cloudfront.net/apt stable main" | tee -a   /etc/apt/sources.list.d/opendistroforelasticsearch.list
RUN wget https://artifacts.elastic.co/downloads/elasticsearch/elasticsearch-oss-7.10.2-amd64.deb && \
    dpkg -i elasticsearch-oss-7.10.2-amd64.deb && \
    rm elasticsearch-oss-7.10.2-amd64.deb

RUN curl https://d3g5vo6xdbdb9a.cloudfront.net/tarball/opendistro-elasticsearch/opendistroforelasticsearch-1.13.0-linux-x64.tar.gz -o opendistroforelasticsearch-1.13.0-linux-x64.tar.gz && \
    tar -zxf opendistroforelasticsearch-1.13.0-linux-x64.tar.gz && \
    rm opendistroforelasticsearch-1.13.0-linux-x64.tar.gz && \
    mv opendistroforelasticsearch-1.13.0 /elasticsearch && \
    chown elasticsearch:elasticsearch elasticsearch -R && \
    cd /elasticsearch && \
    sudo -H -u elasticsearch bash -c './opendistro-tar-install.sh &'

RUN curl -fsSL https://artifacts.elastic.co/GPG-KEY-elasticsearch | apt-key add -
RUN echo "deb https://artifacts.elastic.co/packages/7.x/apt stable main" | tee -a /etc/apt/sources.list.d/elastic-7.x.list
RUN apt update
RUN curl https://d3g5vo6xdbdb9a.cloudfront.net/tarball/opendistroforelasticsearch-kibana/opendistroforelasticsearch-kibana-1.13.0-linux-x64.tar.gz -o opendistroforelasticsearch-kibana-1.13.0-linux-x64.tar.gz && \
    tar -xf opendistroforelasticsearch-kibana-1.13.0-linux-x64.tar.gz && \
    rm opendistroforelasticsearch-kibana-1.13.0-linux-x64.tar.gz

# Prepare environment UTF-8
RUN apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y locales python3 python3-pip mc nano htop git
RUN sed -i -e 's/# en_US.UTF-8 UTF-8/en_US.UTF-8 UTF-8/' /etc/locale.gen && \
    locale-gen
ENV LANG en_US.UTF-8
ENV LANGUAGE en_US:en
ENV LC_ALL en_US.UTF-8

RUN echo "Cloning OSAS" && \
    cd / && \
    git clone https://github.com/adobe/OSAS.git && \
    mv OSAS osas

RUN cd /osas/ && \
    pip3 install --no-cache-dir -r requirements.txt


CMD /osas/scripts/run_services.sh & cd /osas && python3 osas/webserver.py

