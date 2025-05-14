echo "####################"
echo "Uninstalling Docker"
echo "####################"
for pkg in docker.io docker-doc docker-compose podman-docker containerd runc; do sudo apt-get remove $pkg; done

echo "####################"
echo "Updating OS"
echo "####################"
sudo apt-get update && sudo apt-get upgrade -y

# Add Docker's official GPG key:
sudo apt-get install ca-certificates curl
sudo install -m 0755 -d /etc/apt/keyrings
sudo curl -fsSL https://download.docker.com/linux/debian/gpg -o /etc/apt/keyrings/docker.asc
sudo chmod a+r /etc/apt/keyrings/docker.asc

# Add the repository to Apt sources:
echo \
  "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/debian \
  $(. /etc/os-release && echo "$VERSION_CODENAME") stable" | \
  sudo tee /etc/apt/sources.list.d/docker.list > /dev/null
sudo apt-get update

sudo apt-get install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin -y

sudo usermod -aG docker $USER

echo "####################"
echo "Getting Environment Ready"
echo "####################"

mkdir ~/opencti
cd ~/opencti
vi .env

sudo echo "vm.max_map_count=1048575" >> /etc/sysctl.conf

(cat << EOF
OPENCTI_ADMIN_EMAIL=<ChangeMePlease>
OPENCTI_ADMIN_PASSWORD=<ChangeMePlease>
OPENCTI_ADMIN_TOKEN=$(cat /proc/sys/kernel/random/uuid)
OPENCTI_BASE_URL=http://localhost:8080
OPENCTI_HEALTHCHECK_ACCESS_KEY=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_USER=$(cat /proc/sys/kernel/random/uuid)
MINIO_ROOT_PASSWORD=$(cat /proc/sys/kernel/random/uuid)
RABBITMQ_DEFAULT_USER=guest
RABBITMQ_DEFAULT_PASS=guest
ELASTIC_MEMORY_SIZE=4G
CONNECTOR_HISTORY_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_CSV_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_FILE_STIX_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_EXPORT_FILE_TXT_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_IMPORT_DOCUMENT_ID=$(cat /proc/sys/kernel/random/uuid)
CONNECTOR_ANALYSIS_ID=$(cat /proc/sys/kernel/random/uuid)
SMTP_HOSTNAME=localhost
GTI_API_KEY=
URLSCAN_API_KEY=<ChangeMePlease>
ALIENVAULT_API_KEY=<ChangeMePlease>
GREYNOISE_API_KEY=<ChangeMePlease>
OPEN_APPSEC_TOKEN=<ChangeMePlease>
EOF
) > .env

#wget -O default.conf "https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/OpenCTI%20Integration/default.conf"
wget -O docker-compose.yml "https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/OpenCTI%20Integration/docker-compose.yml"
wget -O latest_docker.sh "https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/OpenCTI%20Integration/latest_docker.sh"
chmod 755 latest_docker.sh

cd ~/opencti
mkdir open-appsec-advance-model
cd open-appsec-advance-model
wget -O open-appsec-advanced-model.tgz https://github.com/repulsivityy/VirusTotal/raw/refs/heads/main/OpenCTI%20Integration/open-appsec-advanced-model.tgz
cd ~/opencti

echo "####################"
echo "Bringing OpenCTI up"
echo "####################"
sudo docker compose up -d
