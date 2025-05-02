#!/bin/bash
set -e
############################################################
#   CÀI ĐẶT ELK STACK 8.13.4 + SSL
#   (Giữ nguyên logic gốc – bổ sung tham số user)
#   Tác giả: Lê Nhưt Anh - Email: anh2ln@hcmpc.com.vn – 04/2025
############################################################

####################  BIẾN CHUNG  ##########################
# User sở hữu các file .tar.gz, .p12 (mặc định = user hiện tại)
DEPLOY_USER="${1:-$(whoami)}"

# Lấy đường dẫn $HOME chính xác của DEPLOY_USER
USER_HOME="$(getent passwd "${DEPLOY_USER}" | cut -d: -f6)"
if [[ -z "$USER_HOME" ]]; then
  echo "❌ Không tìm thấy home của user ${DEPLOY_USER}" >&2
  exit 1
fi

BASE_DIR="/opt"
MASTER_HOST="192.168.56.10"
DATA_HOST="192.168.56.11"

# Elasticsearch
ES_VERSION="8.13.4"
ES_TAR="elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz"
ES_DIR="${BASE_DIR}/elasticsearch-${ES_VERSION}"
ES_SYM="${BASE_DIR}/elasticsearch"
ES_USER="elasticsearch"

# Kibana
KIBANA_VERSION="8.13.4"
KIBANA_TAR="kibana-${KIBANA_VERSION}-linux-x86_64.tar.gz"
KIBANA_DIR="${BASE_DIR}/kibana-${KIBANA_VERSION}"
KIBANA_SYM="${BASE_DIR}/kibana"
KIBANA_USER="kibana"

# Logstash
LOGSTASH_VERSION="8.13.4"
LOGSTASH_TAR="logstash-${LOGSTASH_VERSION}-linux-x86_64.tar.gz"
LOGSTASH_DIR="${BASE_DIR}/logstash-${LOGSTASH_VERSION}"
LOGSTASH_SYM="${BASE_DIR}/logstash"
LOGSTASH_USER="logstash"

# File chung
ENV_FILE="${USER_HOME}/elk-passwords.env"
CA_PASS="changeme"
############################################################

echo "1/35 👉 Tạo user Elasticsearch (nếu chưa có)…"
id -u $ES_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $ES_USER

echo "2/35 📦 Giải nén Elasticsearch…"
sudo mkdir -p $BASE_DIR
sudo tar -xzf "${USER_HOME}/${ES_TAR}" -C $BASE_DIR

echo "3/35 🔧 Phân quyền thư mục Elasticsearch…"
sudo chown -R $ES_USER:$ES_USER $ES_DIR

echo "4/35 🔗 Tạo symlink Elasticsearch…"
sudo ln -sfn $ES_DIR $ES_SYM

echo "5/35 ⚙️  Khai báo ES_HOME và PATH…"
echo "export ES_HOME=$ES_SYM"            | sudo tee /etc/profile.d/elasticsearch.sh
echo "export PATH=\$ES_HOME/bin:\$PATH"  | sudo tee -a /etc/profile.d/elasticsearch.sh
sudo chmod +x /etc/profile.d/elasticsearch.sh
source /etc/profile.d/elasticsearch.sh

echo "6/35 🖥️  Tăng vm.max_map_count kernel…"
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144

echo "7/35 📑 Tạo elasticsearch.yml (single-node + security)…"
sudo tee $ES_DIR/config/elasticsearch.yml >/dev/null <<EOF
discovery.type: single-node
xpack.security.enabled: true
xpack.security.authc.api_key.enabled: true
xpack.security.http.ssl:
  enabled: false
network.host: 0.0.0.0
EOF

echo "8/35 🛠️  Tạo service Elasticsearch…"
sudo tee /etc/systemd/system/elasticsearch.service >/dev/null <<EOF
[Unit]
Description=Elasticsearch $ES_VERSION
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
User=$ES_USER
Group=$ES_USER
ExecStart=$ES_DIR/bin/elasticsearch
Restart=always
LimitNOFILE=65535
Environment=ES_JAVA_HOME=$ES_DIR/jdk
[Install]
WantedBy=multi-user.target
EOF

echo "9/35 🚀 Bật & khởi động Elasticsearch…"
sudo systemctl enable elasticsearch
sudo systemctl start  elasticsearch

echo "10/35 ⏳ Đợi Elasticsearch sẵn sàng (HTTP)…"
until curl -s http://localhost:9200 >/dev/null; do sleep 2; done

echo "11/35 🔐 Sinh mật khẩu mặc định…"
sudo -u $ES_USER $ES_DIR/bin/elasticsearch-setup-passwords auto -b > $ENV_FILE
sudo chown "$DEPLOY_USER":"$DEPLOY_USER" $ENV_FILE
ES_PASSWORD=$(grep "PASSWORD elastic" $ENV_FILE | awk '{print $4}')

echo "12/35 🔧 Bật SSL Transport…"
sudo sed -i 's/xpack.security.enabled: true/&\
xpack.security.transport.ssl.enabled: true/' $ES_DIR/config/elasticsearch.yml

###################  KIBANA  ###################
echo "13/35 👉 Tạo user Kibana (nếu chưa có)…"
id -u $KIBANA_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $KIBANA_USER

echo "14/35 📦 Giải nén Kibana…"
sudo tar -xzf "${USER_HOME}/${KIBANA_TAR}" -C $BASE_DIR

echo "15/35 🔧 Phân quyền & symlink Kibana…"
sudo chown -R $KIBANA_USER:$KIBANA_USER $KIBANA_DIR
sudo ln -sfn $KIBANA_DIR $KIBANA_SYM

echo "16/35 📑 Viết kibana.yml (security)…"
sudo tee $KIBANA_DIR/config/kibana.yml >/dev/null <<EOF
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "$(grep "PASSWORD kibana_system" $ENV_FILE | awk '{print $4}')"
telemetry.optIn: false
xpack.security:
  session.idleTimeout: "30m"
  session.lifespan:   "8h"
  encryptionKey: "$(openssl rand -hex 32)"
EOF

echo "17/35 🛠️  Tạo service Kibana…"
sudo tee /etc/systemd/system/kibana.service >/dev/null <<EOF
[Unit]
Description=Kibana $KIBANA_VERSION
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target elasticsearch.service
[Service]
Type=simple
User=$KIBANA_USER
Group=$KIBANA_USER
ExecStart=$KIBANA_DIR/bin/kibana
Restart=always
LimitNOFILE=65535
Environment=NODE_OPTIONS="--max-old-space-size=2048"
[Install]
WantedBy=multi-user.target
EOF

echo "18/35 🚀 Bật & khởi động Kibana…"
sudo systemctl enable kibana
sudo systemctl start  kibana

echo "19/35 ⏳ Đợi Kibana sẵn sàng (HTTP)…"
until curl -s http://localhost:5601 >/dev/null; do sleep 2; done
echo "20/35 ✅ Kibana đã sẵn sàng tại http://localhost:5601"

###################  LOGSTASH  #################
echo "21/35 👉 Tạo user Logstash (nếu chưa có)…"
id -u $LOGSTASH_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $LOGSTASH_USER

echo "22/35 📦 Giải nén Logstash…"
sudo tar -xzf "${USER_HOME}/${LOGSTASH_TAR}" -C $BASE_DIR

echo "23/35 🔧 Phân quyền & symlink Logstash…"
sudo chown -R $LOGSTASH_USER:$LOGSTASH_USER $LOGSTASH_DIR
sudo ln -sfn $LOGSTASH_DIR $LOGSTASH_SYM

echo "24/35 🔐 Tạo role & user logstash_writer…"
LOGSTASH_WRITER_PASSWORD=$(openssl rand -hex 12)
curl -X POST "http://localhost:9200/_security/role/logstash_writer" \
  -u "elastic:${ES_PASSWORD}" -H "Content-Type: application/json" -d '{
    "cluster":["monitor","manage_index_templates"],
    "indices":[{"names":["*"],"privileges":["create_index","write","delete","index","read"]}]
}'
curl -X POST "http://localhost:9200/_security/user/logstash_writer" \
  -u "elastic:${ES_PASSWORD}" -H "Content-Type: application/json" -d '{
    "password":"'"${LOGSTASH_WRITER_PASSWORD}"'",
    "roles":["logstash_writer"]
}'
echo "PASSWORD logstash_writer = ${LOGSTASH_WRITER_PASSWORD}" >> $ENV_FILE

echo "25/35 🗄️  Viết pipeline mẫu…"
sudo mkdir -p /etc/logstash
sudo tee /etc/logstash/sample.conf >/dev/null <<EOF
input { generator { lines => ["Hello, world!", "Logstash is awesome!"] count => 10 } }
output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "test-logs-%{+YYYY.MM.dd}"
    user  => "logstash_writer"
    password => "${LOGSTASH_WRITER_PASSWORD}"
  }
  stdout { codec => rubydebug }
}
EOF
sudo chown -R $LOGSTASH_USER:$LOGSTASH_USER /etc/logstash

echo "26/35 🛠️  Tạo service Logstash…"
sudo tee /etc/systemd/system/logstash.service >/dev/null <<EOF
[Unit]
Description=Logstash ${LOGSTASH_VERSION}
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target elasticsearch.service
[Service]
Type=simple
User=${LOGSTASH_USER}
Group=${LOGSTASH_USER}
ExecStart=${LOGSTASH_SYM}/bin/logstash --path.settings ${LOGSTASH_SYM}/config --path.data /var/lib/logstash -f /etc/logstash/
Restart=always
LimitNOFILE=65535
[Install]
WantedBy=multi-user.target
EOF

echo "27/35 📂 Tạo /var/lib/logstash & cấp quyền…"
sudo mkdir -p /var/lib/logstash
sudo chown -R $LOGSTASH_USER:$LOGSTASH_USER /var/lib/logstash

echo "28/35 🚀 Bật & khởi động Logstash…"
sudo systemctl daemon-reload
sudo systemctl enable logstash
sudo systemctl start  logstash

echo "29/35 ⏳ Đợi API monitoring Logstash…"
until curl -s http://localhost:9600/_node/pipelines >/dev/null; do sleep 2; done

###################  SSL  ####################
echo "30/35 🔒 Bật SSL HTTP & Transport…"
sudo sed -i '/^xpack\.security\.http\.ssl:/,/^  enabled: false/d' $ES_SYM/config/elasticsearch.yml
sudo sed -i '/^xpack\.security\.transport\.ssl\.enabled: true/d' $ES_SYM/config/elasticsearch.yml
sudo rm -f $ES_SYM/config/elasticsearch.yml
sudo touch $ES_SYM/config/elasticsearch.yml
sudo chown $ES_USER:$ES_USER $ES_SYM/config/elasticsearch.yml
sudo tee -a $ES_SYM/config/elasticsearch.yml >/dev/null <<EOF

cluster.name: elk-single
node.name: master-1
node.roles: [master, data]
network.host: 0.0.0.0
transport.bind_host: $MASTER_HOST
cluster.initial_master_nodes: ["master-1"]
discovery.seed_hosts: ["$MASTER_HOST", "$DATA_HOST"]
network.publish_host: $MASTER_HOST

# ---- SSL ----
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.type: PKCS12
xpack.security.http.ssl.keystore.path: elasticsearch.p12
xpack.security.http.ssl.keystore.password: $CA_PASS
xpack.security.http.ssl.truststore.path: elasticsearch.p12
xpack.security.http.ssl.truststore.password: $CA_PASS
xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.type: PKCS12
xpack.security.transport.ssl.keystore.path: elasticsearch.p12
xpack.security.transport.ssl.keystore.password: $CA_PASS
xpack.security.transport.ssl.truststore.type: PKCS12
xpack.security.transport.ssl.truststore.path: elasticsearch.p12
xpack.security.transport.ssl.truststore.password: $CA_PASS
EOF

sudo systemctl restart elasticsearch

echo "31/35 🔒 Sinh CA & keystore elasticsearch.p12…"
sudo rm -f $ES_DIR/config/elastic-stack-ca.p12 $ES_DIR/config/elasticsearch.p12
printf '%s\n%s\n' $CA_PASS $CA_PASS | \
  sudo $ES_SYM/bin/elasticsearch-certutil ca --silent --pass $CA_PASS \
       --out $ES_DIR/config/elastic-stack-ca.p12
printf '%s\n%s\n' $CA_PASS $CA_PASS | \
  sudo $ES_SYM/bin/elasticsearch-certutil cert --name elasticsearch --ca $ES_DIR/config/elastic-stack-ca.p12 \
       --silent --ca-pass $CA_PASS --pass $CA_PASS --out $ES_DIR/config/elasticsearch.p12
sudo chown $ES_USER:$ES_USER $ES_DIR/config/*.p12
sudo chmod 640              $ES_DIR/config/*.p12

echo "32/35 🔁 Khởi động lại Elasticsearch (HTTPS)…"
sudo systemctl restart elasticsearch
until curl -ks https://localhost:9200 >/dev/null; do sleep 2; done

echo "33/35 🔒 Sinh chứng chỉ Kibana & cấu hình TLS…"
sudo /opt/elasticsearch/bin/elasticsearch-certutil cert --name kibana --ca $ES_DIR/config/elastic-stack-ca.p12 \
     --silent --ca-pass $CA_PASS --pass $CA_PASS --out $KIBANA_DIR/config/kibana.p12
sudo openssl pkcs12 -in $KIBANA_DIR/config/kibana.p12 -nocerts -nodes -passin pass:$CA_PASS | \
     sudo tee $KIBANA_DIR/config/kibana.key >/dev/null
sudo openssl pkcs12 -in $KIBANA_DIR/config/kibana.p12 -clcerts -nokeys -passin pass:$CA_PASS \
     -out $KIBANA_DIR/config/kibana.crt
sudo openssl pkcs12 -in $ES_DIR/config/elastic-stack-ca.p12 -nokeys -clcerts -passin pass:$CA_PASS \
     -out $KIBANA_DIR/config/elastic-stack-ca.pem
sudo chown $KIBANA_USER:$KIBANA_USER $KIBANA_DIR/config/kibana.* $KIBANA_DIR/config/elastic-stack-ca.pem
sudo chmod 640 $KIBANA_DIR/config/kibana.* $KIBANA_DIR/config/elastic-stack-ca.pem
sudo sed -i '/^elasticsearch\.hosts:/d' $KIBANA_DIR/config/kibana.yml
sudo tee -a $KIBANA_DIR/config/kibana.yml >/dev/null <<EOF

# --- TLS ---
server.ssl.enabled: true
server.ssl.certificate: $KIBANA_DIR/config/kibana.crt
server.ssl.key:         $KIBANA_DIR/config/kibana.key
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.ssl.certificateAuthorities: ["$KIBANA_DIR/config/elastic-stack-ca.pem"]
elasticsearch.ssl.verificationMode: certificate
EOF
sudo systemctl restart kibana
until curl -ks https://localhost:5601 >/dev/null; do sleep 2; done

echo "34/35 🔒 Sinh chứng chỉ Logstash & chỉnh pipeline SSL…"
sudo /opt/elasticsearch/bin/elasticsearch-certutil cert --name logstash --ca $ES_DIR/config/elastic-stack-ca.p12 \
     --silent --ca-pass $CA_PASS --pass $CA_PASS --out $LOGSTASH_DIR/config/logstash.p12
sudo openssl pkcs12 -in $LOGSTASH_DIR/config/logstash.p12 -nocerts -nodes -passin pass:$CA_PASS | \
     sudo tee $LOGSTASH_DIR/config/logstash.key >/dev/null
sudo openssl pkcs12 -in $LOGSTASH_DIR/config/logstash.p12 -clcerts -nokeys -passin pass:$CA_PASS \
     -out $LOGSTASH_DIR/config/logstash.crt
sudo cp $KIBANA_DIR/config/elastic-stack-ca.pem $LOGSTASH_DIR/config/
sudo chown $LOGSTASH_USER:$LOGSTASH_USER $LOGSTASH_DIR/config/logstash.* $LOGSTASH_DIR/config/elastic-stack-ca.pem
sudo chmod 640 $LOGSTASH_DIR/config/logstash.* $LOGSTASH_DIR/config/elastic-stack-ca.pem
sudo sed -i -e 's|\(\s*hosts\s*=>\s*\)\["http://|\1["https://|g' \
            -e '/^\s*hosts\s*=>/a \    ssl_certificate_verification => false\n    ssl => true\n    cacert => "'"$LOGSTASH_DIR/config/elastic-stack-ca.pem"'"' \
            /etc/logstash/sample.conf
sudo systemctl restart logstash

sudo cp /opt/elasticsearch/config/elastic-stack-ca.p12 /home/$USER_HOME

echo "35/35 ✅ Hoàn tất! ELK đang chạy HTTPS. Mật khẩu lưu tại $ENV_FILE"
