#!/bin/bash
set -e
############################################################
#   AUTO-INSTALL EXTRA ELASTICSEARCH NODE (SSL-aware)
#   Oracle Linux / CentOS / RHEL 8
#   04-2025
############################################################

############## TÙY CHỈNH NHANH ##############
MASTER_IP="192.168.56.11"      # IP / hostname node master (nếu muốn join)
CLUSTER_NAME="elk-single"      # giống master
NODE_NAME="data-1"             # tên node phụ
ES_VERSION="8.13.4"
CA_PASS="changeme"             # passphrase khi master tạo CA
#############################################

BASE_DIR="/opt"
ES_TAR="elasticsearch-${ES_VERSION}-linux-x86_64.tar.gz"
ES_DIR="${BASE_DIR}/elasticsearch-${ES_VERSION}"
ES_SYM="${BASE_DIR}/elasticsearch"
ES_USER="elasticsearch"

HOME_CA="$HOME/elastic-stack-ca.p12"          # CA đặt tạm ở /home/vagrant/
NODE_P12="${ES_DIR}/config/${NODE_NAME}.p12"

# ----------------------------------------------------------
echo "👉 [1/18] Tạo user hệ thống elasticsearch (nếu chưa có)…"
id -u $ES_USER &>/dev/null || sudo useradd --system --no-create-home --shell /sbin/nologin $ES_USER

echo "📦 [2/18] Giải nén Elasticsearch $ES_VERSION…"
sudo mkdir -p $BASE_DIR
sudo tar -xzf $HOME/$ES_TAR -C $BASE_DIR
sudo ln -sfn $ES_DIR $ES_SYM
sudo chown -R $ES_USER:$ES_USER $ES_DIR

echo "🖥️  [3/18] Tăng vm.max_map_count kernel…"
echo "vm.max_map_count=262144" | sudo tee -a /etc/sysctl.conf
sudo sysctl -w vm.max_map_count=262144

# ----------------------------------------------------------
if [[ -f "$HOME_CA" ]]; then
  echo "🔒 [4/18] Phát hiện CA → cấu hình SSL để join cluster."
  sudo cp "$HOME_CA" "$ES_DIR/config/elastic-stack-ca.p12"
  sudo chown $ES_USER:$ES_USER "$ES_DIR/config/elastic-stack-ca.p12"
  sudo chmod 640 "$ES_DIR/config/elastic-stack-ca.p12"

  echo "🔑 [5/18] Sinh keystore PKCS12 cho node…"
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
xpack.security.transport.ssl.keystore.path: ${NODE_NAME
