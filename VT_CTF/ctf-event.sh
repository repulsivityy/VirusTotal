echo "####################"
echo "Updating OS"
echo "####################"
sudo apt-get update && sudo apt-get upgrade -y

echo "####################"
echo "Instaling Docker"
echo "####################"
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

# Run VT CTF
echo "####################"
echo " Getting the VT CTF env ready"
echo "####################"
wget https://raw.githubusercontent.com/repulsivityy/VirusTotal/main/VT_CTF/compose.yaml
sudo docker compose up -d


echo "####################"
echo " Connecting to the VT CTF"
echo "####################"
myip="$(curl -s ipinfo.io/ip)"
echo "Connect to http://$myip:8000"