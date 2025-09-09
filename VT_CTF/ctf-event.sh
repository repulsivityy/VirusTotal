#!/bin/bash

echo "####################"
echo "CTF Setup Script"
echo "####################"

# Ask the user if they want to update the OS and install Docker
echo "Do you need to update the OS and install Docker? (y/n)"
read install_docker_choice

# Convert input to lowercase for consistent checking
install_docker_choice_lower=$(echo "$install_docker_choice" | tr '[:upper:]' '[:lower:]')

if [[ "$install_docker_choice_lower" == "y" || "$install_docker_choice_lower" == "yes" ]]; then
    echo "####################"
    echo "Updating OS"
    echo "####################"
    sudo apt-get update && sudo apt-get upgrade -y

    echo "####################"
    echo "Installing Docker"
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
else
    echo "Skipping OS update and Docker installation."
fi

# Chose which CTF to run:
echo "####################"
echo "Please choose which CTF to run. Enter only the number."
echo "####################"
echo "1 - Golden GTI CTF"
echo "2 - GUS CTF"
echo "3 - Dom's GTI CTF"
echo "4 - VT CTF"
read choice

# Validate the input
while [[ "$choice" != "1" && "$choice" != "2" && "$choice" != "3" && "$choice" != "4" ]]; do
  echo "Invalid choice. Please enter 1, 2, 3, or 4."
  read choice
done

# Run CTF
echo "####################"
echo "Getting the CTF environment ready"
echo "####################"

# Clear any previous compose file to ensure the correct one is downloaded
rm -f compose.yaml
wget https://raw.githubusercontent.com/repulsivityy/VirusTotal/refs/heads/main/VT_CTF/compose.yaml

if [ "$choice" == "1" ]; then
  sudo docker compose --profile tarah up -d
elif [ "$choice" == "2" ]; then
  sudo docker compose --profile gus up -d
elif [ "$choice" == "3" ]; then
  sudo docker compose --profile domgti up -d
else 
  sudo docker compose --profile vt up -d
fi

echo "####################"
echo "Connecting to the CTF"
echo "####################"
myip="$(curl -s ipinfo.io/ip)"
echo "Connect to http://$myip:8000"