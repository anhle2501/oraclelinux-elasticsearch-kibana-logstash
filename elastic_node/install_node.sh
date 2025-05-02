#!/bin/bash
set -euo pipefail

################################################################
#  AUTO-INSTALL EXTRA ELASTICSEARCH NODE (SSL-aware)
#  Oracle Linux / CentOS / RHEL 8
#  04-2025 / Author: Lê Nhựt Anh 
################################################################

############## TÙY CHỈNH NHANH ##############
MASTER_IP="192.168.56.10"      # IP hoặc hostname của node master
CLUSTER_NAME="elk-single"      # Tên cluster phải giống master
NODE_NAME="data-1"             # Tên node phụ
ES_VERSION="8.13.4"
CA_PASS="changeme"             # Passphrase của CA
#############################################

BASE_DIR="/opt"
ES_TAR="elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz"
ES_DIR="${BASE_DIR}/elasticsearch-${ES_VERSION}"
ES_SYM="${BASE_DIR}/elasticsearch"
ES_USER="elasticsearch"
HOME="/home/vagrant"

HOME_CA="$HOME/elastic-stack-ca.p12"          # File CA đã copy từ master
NODE_P12="${ES_DIR}/config/${NODE_NAME}.p12"

# ----------------------------------------------------------
echo "👉 [1/9] Tạo user hệ thống elasticsearch (nếu chưa có)…"
id -u $ES_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $ES_USER

echo "📦 [2/9] Giải nén Elasticsearch $ES_VERSION…"
sudo mkdir -p $BASE_DIR
sudo tar -xzf $HOME/$ES_TAR -C $BASE_DIR
sudo ln -sfn $ES_DIR $ES_SYM
sudo chown -R $ES_USER:$ES_USER $ES_DIR

echo "🖥️  [3/9] Tăng vm.max_map_count kernel…"
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144

# ----------------------------------------------------------
if [[ -f "$HOME_CA" ]]; then
  echo "🔒 [4/9] Phát hiện CA → cấu hình SSL để join cluster."
  sudo cp "$HOME_CA" "$ES_DIR/config/elastic-stack-ca.p12"
  sudo chown $ES_USER:$ES_USER "$ES_DIR/config/elastic-stack-ca.p12"
  sudo chmod 640 "$ES_DIR/config/elastic-stack-ca.p12"

  echo "🔑 [5/9] Sinh keystore PKCS12 cho node…"
  printf '%s\n%s\n' "$CA_PASS" "$CA_PASS" | \
   sudo $ES_DIR/bin/elasticsearch-certutil cert \
        --name "$NODE_NAME" --ca "$ES_DIR/config/elastic-stack-ca.p12" \
        --silent --ca-pass "$CA_PASS" --pass "$CA_PASS" --out "$NODE_P12"
  sudo chown $ES_USER:$ES_USER "$NODE_P12"
  sudo chmod 640 "$NODE_P12"

  SSL_BLOCK=$(cat <<SSL
xpack.security.enabled: true
xpack.security.http.ssl.enabled: true
xpack.security.http.ssl.keystore.path: ${NODE_NAME}.p12
xpack.security.http.ssl.keystore.password: ${CA_PASS}
xpack.security.http.ssl.truststore.path: ${NODE_NAME}.p12
xpack.security.http.ssl.truststore.password: ${CA_PASS}

xpack.security.transport.ssl.enabled: true
xpack.security.transport.ssl.verification_mode: certificate
xpack.security.transport.ssl.keystore.path: ${NODE_NAME}.p12
xpack.security.transport.ssl.keystore.password: ${CA_PASS}
xpack.security.transport.ssl.truststore.path: ${NODE_NAME}.p12
xpack.security.transport.ssl.truststore.password: ${CA_PASS}
SSL
)

  echo "⚙️  [6/9] Cập nhật elasticsearch.yml…"
  sudo tee $ES_DIR/config/elasticsearch.yml >/dev/null <<EOF
cluster.name: $CLUSTER_NAME
node.name: $NODE_NAME
network.host: 0.0.0.0
network.publish_host: $(hostname -I | awk '{print $2}')
discovery.seed_hosts: ["$MASTER_IP"]
$SSL_BLOCK
EOF

else
  echo "⚠️  [4/9] Không phát hiện CA → bỏ qua SSL (standalone mode)."
fi

# ----------------------------------------------------------
echo "🛠️  [7/9] Tạo systemd service elasticsearch…"
sudo tee /etc/systemd/system/elasticsearch.service >/dev/null <<EOF
[Unit]
Description=Elasticsearch
Wants=network-online.target
After=network-online.target

[Service]
User=$ES_USER
Group=$ES_USER
ExecStart=$ES_DIR/bin/elasticsearch
Restart=on-failure
LimitNOFILE=65535
Environment=ES_JAVA_HOME=$ES_DIR/jdk

[Install]
WantedBy=multi-user.target
EOF

sudo systemctl daemon-reload
sudo systemctl enable elasticsearch

# ----------------------------------------------------------
echo "🚀 [8/9] Khởi động Elasticsearch node phụ…"
sudo systemctl start elasticsearch

echo "⏳ [9/9] Đợi node HTTPS 9200 sẵn sàng…"
until curl -ks https://localhost:9200 >/dev/null; do sleep 5; done
echo "✅ Node $NODE_NAME đã chạy HTTPS và SSL hoàn tất."
