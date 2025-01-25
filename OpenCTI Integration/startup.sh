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
mkdir ~/opencti/open-appsec
mkdir ~/opencti/open-appsec/conf
mkdir ~/opencti/open-appsec/data
mkdir ~/opencti/open-appsec/logs

cd ~/opencti

wget -O default.conf "https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/OpenCTI%20Integration/default.conf"
wget -O docker-compose.yml "https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/OpenCTI%20Integration/docker-compose.yml"
wget -O latest_docker.sh "https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/OpenCTI%20Integration/latest_docker.sh"
chmod 755 latest_docker.sh

echo "####################"
echo "Bringing OpenCTI up"
echo "####################"
sudo docker compose up -d
