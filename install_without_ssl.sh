#!/bin/bash


set -e


######################################
# Install Elasticsearch with Security
######################################


ES_VERSION="8.13.4"
ES_TAR="elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz"
ES_DIR="/opt/elasticsearch-${ES_VERSION}"
ES_USER="elasticsearch"
ENV_FILE="/home/vagrant/elasticsearch-passwords.env"


echo "👉 Creating elasticsearch user (if not exists)..."
id -u $ES_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $ES_USER


echo "📦 Extracting Elasticsearch tarball..."
sudo mkdir -p /opt
sudo tar -xzf /home/vagrant/${ES_TAR} -C /opt


echo "🔧 Setting permissions..."
sudo chown -R $ES_USER:$ES_USER $ES_DIR


echo "🔧 Creating symbolic link..."
sudo ln -sfn $ES_DIR /opt/elasticsearch


echo "⚙️ Setting up environment variables..."
echo "export ES_HOME=/opt/elasticsearch" | sudo tee /etc/profile.d/elasticsearch.sh
echo "export PATH=\$ES_HOME/bin:\$PATH" | sudo tee -a /etc/profile.d/elasticsearch.sh
sudo chmod +x /etc/profile.d/elasticsearch.sh
source /etc/profile.d/elasticsearch.sh


echo "🔧 Fixing vm.max_map_count for Elasticsearch..."
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144


echo "🔧 Configuring single-node with security enabled..."
sudo tee $ES_DIR/config/elasticsearch.yml > /dev/null <<EOF
discovery.type: single-node
xpack.security.enabled: true
xpack.security.authc.api_key.enabled: true
xpack.security.http.ssl:
  enabled: false
network.host: 0.0.0.0
EOF


echo "🛠️ Creating systemd service for Elasticsearch..."
sudo tee /etc/systemd/system/elasticsearch.service > /dev/null <<EOF
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


echo "🚀 Enabling and starting Elasticsearch..."
sudo systemctl enable elasticsearch
sudo systemctl start elasticsearch


echo "⏳ Waiting for Elasticsearch to be ready..."
until curl -s http://localhost:9200 > /dev/null; do
  sleep 2
done


echo "🔐 Setting up Elasticsearch passwords..."
echo "⏳ This may take a minute..."
sudo -u $ES_USER $ES_DIR/bin/elasticsearch-setup-passwords auto -b > $ENV_FILE
chown vagrant:vagrant $ENV_FILE


echo "🔑 Generated passwords saved to $ENV_FILE"
echo "🔍 Displaying generated passwords:"
cat $ENV_FILE


# Update Elasticsearch config with the generated credentials
ES_PASSWORD=$(grep "PASSWORD elastic" $ENV_FILE | awk '{print $4}')
sudo sed -i "s/xpack.security.enabled: true/&\nxpack.security.transport.ssl.enabled: true/" $ES_DIR/config/elasticsearch.yml


# ---------------------------------------
# Install Kibana with Security
# ---------------------------------------


KIBANA_VERSION="8.13.4"
KIBANA_TAR="kibana-${KIBANA_VERSION}-linux-x86_64.tar.gz"
KIBANA_DIR="/opt/kibana-${KIBANA_VERSION}"
KIBANA_USER="kibana"


echo "👉 Creating kibana user (if not exists)..."
id -u $KIBANA_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $KIBANA_USER


echo "📦 Extracting Kibana tarball..."
sudo mkdir -p /opt
sudo tar -xzf /home/vagrant/${KIBANA_TAR} -C /opt


echo "🔧 Setting permissions..."
sudo chown -R $KIBANA_USER:$KIBANA_USER $KIBANA_DIR


echo "🔧 Creating symbolic link for Kibana..."
sudo ln -sfn $KIBANA_DIR /opt/kibana


echo "⚙️ Configuring Kibana with security..."
sudo tee $KIBANA_DIR/config/kibana.yml > /dev/null <<EOF
server.host: "0.0.0.0"
elasticsearch.hosts: ["http://localhost:9200"]
elasticsearch.username: "kibana_system"
elasticsearch.password: "$(grep "PASSWORD kibana_system" $ENV_FILE | awk '{print $4}')"
telemetry.optIn: false
# Correct security configuration for Kibana 8.x
xpack.security:
  session:
    idleTimeout: "30m"
    lifespan: "8h"
  encryptionKey: "$(openssl rand -hex 32)"
EOF


echo "🛠️ Creating Kibana systemd service..."
sudo tee /etc/systemd/system/kibana.service > /dev/null <<EOF
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


echo "🚀 Enabling and starting Kibana..."
sudo systemctl enable kibana
sudo systemctl start kibana


echo "⏳ Waiting for Kibana to be ready..."
until curl -s http://localhost:5601 > /dev/null; do
  sleep 2
done


echo "✅ Successfully installed Kibana $KIBANA_VERSION with security!"
echo "📍 Access: http://localhost:5601"
echo "🔑 Use the 'elastic' user password from $ENV_FILE to log in"


######################################
# Install Logstash
######################################


LOGSTASH_VERSION="8.13.4"
LOGSTASH_TAR="logstash-${LOGSTASH_VERSION}-linux-x86_64.tar.gz"
LOGSTASH_DIR="/opt/logstash-${LOGSTASH_VERSION}"
LOGSTASH_SYMLINK="/opt/logstash"
LOGSTASH_USER="logstash"


echo "👉 Creating logstash user (if not exists)..."
id -u $LOGSTASH_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $LOGSTASH_USER


echo "📦 Extracting Logstash tarball..."
sudo mkdir -p /opt
sudo tar -xzf /home/vagrant/${LOGSTASH_TAR} -C /opt


echo "🔧 Setting permissions..."
sudo chown -R $LOGSTASH_USER:$LOGSTASH_USER $LOGSTASH_DIR


echo "🔧 Creating symbolic link for Logstash..."
sudo ln -sfn $LOGSTASH_DIR $LOGSTASH_SYMLINK


echo "🔐 Creating logstash_writer role and user..."
LOGSTASH_WRITER_PASSWORD=$(openssl rand -hex 12)  # Generates 24-character password

# Create role
curl -X POST "http://localhost:9200/_security/role/logstash_writer" \
  -u "elastic:${ES_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "cluster": ["monitor", "manage_index_templates"],
    "indices": [
      {
        "names": ["*"],
        "privileges": ["create_index", "write", "delete", "index", "read"]
      }
    ]
  }'

# Create user with secure password
curl -X POST "http://localhost:9200/_security/user/logstash_writer" \
  -u "elastic:${ES_PASSWORD}" \
  -H "Content-Type: application/json" \
  -d '{
    "password": "'"${LOGSTASH_WRITER_PASSWORD}"'",
    "roles": ["logstash_writer"],
    "full_name": "Logstash Writer User"
  }'

# Update the environment file with the new password
echo "PASSWORD logstash_writer = ${LOGSTASH_WRITER_PASSWORD}" >> $ENV_FILE

echo "🗂️  Preparing pipeline directory with secure configuration..."
sudo mkdir -p /etc/logstash
sudo tee /etc/logstash/sample.conf > /dev/null <<EOF
input {
  generator {
    lines => ["Hello, world!", "Logstash is awesome!"]
    count => 10
  }
}

output {
  elasticsearch {
    hosts => ["http://localhost:9200"]
    index => "test-logs-%{+YYYY.MM.dd}"
    user => "logstash_writer"
    password => "${LOGSTASH_WRITER_PASSWORD}"
  }
  stdout {
    codec => rubydebug
  }
}
EOF
sudo chown -R $LOGSTASH_USER:$LOGSTASH_USER /etc/logstash

echo "🛠️ Creating Logstash systemd service..."
sudo tee /etc/systemd/system/logstash.service > /dev/null <<EOF
[Unit]
Description=Logstash ${LOGSTASH_VERSION}
Documentation=https://www.elastic.co
Wants=network-online.target
After=network-online.target elasticsearch.service


[Service]
Type=simple
User=${LOGSTASH_USER}
Group=${LOGSTASH_USER}
ExecStart=${LOGSTASH_SYMLINK}/bin/logstash \\
  --path.settings ${LOGSTASH_SYMLINK}/config \\
  --path.data /var/lib/logstash \\
  -f /etc/logstash/
Restart=always
LimitNOFILE=65535


[Install]
WantedBy=multi-user.target
EOF


echo "📂 Creating data directory..."
sudo mkdir -p /var/lib/logstash
sudo chown -R $LOGSTASH_USER:$LOGSTASH_USER /var/lib/logstash


echo "🚀 Enabling and starting Logstash..."
sudo systemctl daemon-reload
sudo systemctl enable logstash
sudo systemctl start logstash


echo "⏳ Waiting for Logstash monitoring API..."
until curl -s http://localhost:9600/_node/pipelines > /dev/null; do
  sleep 2
done


echo "✅ Successfully installed Logstash ${LOGSTASH_VERSION} with security!"
echo "📍 Logstash monitoring API: http://localhost:9600"


######################################
# Enable SSL on Elasticsearch, Kibana, and Logstash
######################################

CERT_DIR="/opt/elasticsearch/config"
CERT_NAME="elasticsearch"

# 1. Enable SSL on Elasticsearch
echo "🔧 Enabling SSL for Elasticsearch..."
sudo sed -i '/^xpack\.security\.http\.ssl:/,/^  enabled: false/d' /opt/elasticsearch/config/elasticsearch.yml
sudo sed -i '/^xpack\.security\.transport\.ssl\.enabled: true/d' /opt/elasticsearch/config/elasticsearch.yml

sudo tee -a $ES_DIR/config/elasticsearch.yml > /dev/null <<EOF
# ---- SSL ----
xpack.security.http.ssl.enabled:               true
xpack.security.http.ssl.keystore.type:        PKCS12
xpack.security.http.ssl.keystore.path:        elasticsearch.p12
xpack.security.http.ssl.keystore.password:    changeme
xpack.security.http.ssl.truststore.path:      elasticsearch.p12
xpack.security.http.ssl.truststore.password:  changeme

xpack.security.transport.ssl.enabled:         true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.type:   PKCS12
xpack.security.transport.ssl.keystore.path:   elasticsearch.p12
xpack.security.transport.ssl.keystore.password: changeme
xpack.security.transport.ssl.truststore.type: PKCS12
xpack.security.transport.ssl.truststore.path: elasticsearch.p12
xpack.security.transport.ssl.truststore.password: changeme

EOF

sudo rm -f $ES_DIR/config/elastic-stack-ca.p12
printf 'changeme\nchangeme\n' | sudo $ES_DIR/bin/elasticsearch-certutil ca --silent --pass changeme --out $ES_DIR/config/elastic-stack-ca.p12 
# elastic-stack-ca.p12 not use, just use it for elasticsearch.p12

sudo chown elasticsearch:elasticsearch /opt/elasticsearch/config/elastic-stack-ca.p12
sudo chmod 640 /opt/elasticsearch/config/elastic-stack-ca.p12

sudo rm -f $ES_DIR/config/elasticsearch.p12
printf 'changeme\nchangeme\n' | sudo $ES_DIR/bin/elasticsearch-certutil cert --name elasticsearch  --ca $ES_DIR/config/elastic-stack-ca.p12 --silent --ca-pass  changeme --pass changeme --out $ES_DIR/config/elasticsearch.p12

sudo chown elasticsearch:elasticsearch /opt/elasticsearch/config/elasticsearch.p12
sudo chmod 640 /opt/elasticsearch/config/elasticsearch.p12

echo "🚀 Enabling and starting Elasticsearch..."
sudo systemctl stop elasticsearch
sudo systemctl start elasticsearch    

echo "⏳ Waiting for Elasticsearch with SSL to be ready..."
until curl -s --insecure https://localhost:9200 > /dev/null; do
  sleep 2
done


 ######################################
# Enable SSL on Kibana
######################################

echo "🔧 Generating Kibana SSL cert (signed by our CA)…"

# 1. Generate a PKCS#12 “node” cert for Kibana, signed by your CA
 sudo /opt/elasticsearch/bin/elasticsearch-certutil cert \
      --name kibana \
      --ca   /opt/elasticsearch/config/elastic-stack-ca.p12 \
      --silent \
      --ca-pass  changeme \
      --pass     changeme \
      --out  /opt/kibana/config/kibana.p12


# 2. Extract the private key and certificate into separate files
sudo openssl pkcs12 -in /opt/kibana/config/kibana.p12 \
    -nocerts -nodes -passin pass:changeme \
  | sudo tee /opt/kibana/config/kibana.key >/dev/null

sudo openssl pkcs12 -in /opt/kibana/config/kibana.p12 \
    -clcerts -nokeys -passin pass:changeme \
  -out /opt/kibana/config/kibana.crt

# 3. Secure the files for the kibana user
sudo chown kibana:kibana /opt/kibana/config/kibana.*  
sudo chmod 640               /opt/kibana/config/kibana.*

# 4. (Optional) If you haven’t already, extract your CA’s public cert to PEM,
#    so Kibana can trust Elasticsearch:
sudo openssl pkcs12 \
  -in /opt/elasticsearch/config/elastic-stack-ca.p12 \
  -passin pass:changeme \
  -nokeys \
  -clcerts \
  -out /opt/elasticsearch/config/elastic-stack-ca.pem

sudo cp /opt/elasticsearch/config/elastic-stack-ca.pem /opt/kibana/config/

sudo chown kibana:kibana /opt/kibana/config/elastic-stack-ca.pem
sudo chmod 640 /opt/kibana/config/elastic-stack-ca.pem
sudo sed -i '/^elasticsearch\.hosts: \["http:\/\/localhost:9200"\]/d' /opt/kibana/config/kibana.yml

# Append SSL settings to kibana.yml
sudo tee -a /opt/kibana/config/kibana.yml > /dev/null <<EOF

# --- TLS for Kibana HTTP server ---
server.ssl.enabled: true
server.ssl.certificate: /opt/kibana/config/kibana.crt
server.ssl.key:         /opt/kibana/config/kibana.key

# --- Talk to Elasticsearch over HTTPS ---
elasticsearch.hosts: ["https://localhost:9200"]
elasticsearch.ssl.verificationMode: certificate
elasticsearch.ssl.certificateAuthorities: ["/opt/kibana/config/elastic-stack-ca.pem"]
EOF

echo "🚀 Enabling and starting kibana..."
sudo systemctl stop kibana
sudo systemctl start kibana

echo "⏳ Waiting for Kibana with SSL to be ready..."
until curl -s --insecure https://localhost:5601 > /dev/null; do
  sleep 2
done


######################################
# Install Logstash
#####################################
echo "🔧 Enabling SSL for Logstash..."

sudo cp /opt/elasticsearch/config/elastic-stack-ca.pem /opt/logstash/config

#Generate a PKCS#12 “node” cert for Kibana, signed by your CA
 sudo /opt/elasticsearch/bin/elasticsearch-certutil cert \
      --name logstash \
      --ca   /opt/elasticsearch/config/elastic-stack-ca.p12 \
      --silent \
      --ca-pass  changeme \
      --pass     changeme \
      --out  /opt/logstash/config/logstash.p12

#Extract the private key and certificate into separate files
sudo openssl pkcs12 -in /opt/logstash/config/logstash.p12 \
    -nocerts -nodes -passin pass:changeme \
  | sudo tee /opt/logstash/config/logstash.key >/dev/null

sudo openssl pkcs12 -in /opt/logstash/config/logstash.p12 \
    -clcerts -nokeys -passin pass:changeme \
  -out /opt/logstash/config/logstash.crt

sudo chown logstash:logstash /opt/logstash/config/logstash.*  
sudo chmod 640               /opt/logstash/config/logstash.*

sudo chown logstash:logstash /opt/logstash/config/elastic-stack-ca.pem
sudo chmod 640               /opt/logstash/config/elastic-stack-ca.pem

# change yaml config file from http to https
sudo sed -i -e 's|\(\s*hosts\s*=>\s*\)\["http://|\1["https://|g' \
-e '/^\s*hosts\s*=>/a \    ssl_certificate_verification => false\n    ssl => true\n    cacert => "/opt/logstash/config/elastic-stack-ca.pem"' \
/etc/logstash/sample.conf

echo "🚀 Enabling and starting logstash..."
sudo systemctl stop logstash
sudo systemctl start logstash

echo "✅ Elasticsearch, Kibana, and Logstash are now running with SSL enabled."
