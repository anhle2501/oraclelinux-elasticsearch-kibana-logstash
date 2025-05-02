sudo systemctl status elasticsearch

sudo systemctl restart elasticsearch

sudo journalctl -u elasticsearch -f

 vagrant up --provision

 vagrant delete -f

 vagrant ssh
 
 sudo vi /opt/elasticsearch/config/elasticsearch.yml

#mount networkcard
sudo nmcli con add ifname enp0s8 con-name enp0s8 ip4 192.168.56.11/24 type ethernet 
sudo nmcli con up enp0s8