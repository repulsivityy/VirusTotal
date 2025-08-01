echo "####################"
echo "Updating OS"
echo "####################"
sudo apt-get update && sudo apt-get upgrade -y

echo "####################"
echo "Instaling Docker"
echo "####################"
# Add Docker's official GPG key:
sudo apt-get install ca-certificates curl -y
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

# Chose which CTF to run:
echo "####################"
echo "Please choose which CTF to run. Enter only the number."
echo "####################"
echo "1 - Golden GTI CTF"
echo "2 - GUS CTF"
echo "3 - Dom's CTF"
#echo "VT CTF"
read choice

# Validate the input
while [[ "$choice" != "1" && "$choice" != "2" && "$choice" != "3"]]; do
  echo "Invalid choice. Please enter 1, 2 or 3."
  read choice
done

# Run CTF
echo "####################"
echo " Getting the GTI CTF env ready"
echo "####################"
wget https://raw.githubusercontent.com/repulsivityy/VirusTotal/main/VT_CTF/compose.yaml
if [ "$choice" == "1" ]; then
  sudo docker compose --profile tarah up -d
elif ["$choice" == "2" ]; then
  sudo docker compose --profile gus up -d
else
  sudo docker compose --profile dom up -d
fi

echo "####################"
echo " Connecting to the GTI CTF"
echo "####################"
myip="$(curl -s ipinfo.io/ip)"
echo "Connect to http://$myip:8000"