#!/bin/bash
#	
#	Requirement Installation
#	Created by: Squishy
#


tabulate_install(){
	if python3 -c 'import pkgutil; exit(not pkgutil.find_loader("tabulate"))' &> /dev/null; then
		echo "[*] You have it already!!!"
		echo "[*] You can start using 'amipawned' now!!!"
	else
		echo "[!] Installing tabulate" >> install.log
		pip3 install tabulate >> install.log
		echo "[!] Installing tabulate Completed!!!" >> install.log
		echo 
		echo "[*] Your ready now!!!" 
	fi
}

pip3_install(){
	echo "[!] Installing Pip3!!!" >> install.log
	sudo apt-get install python-pip3 >> install.log
	echo "[!] Installing Pip3 Completed!!!" >> install.log
	echo "[*] Pip3 Installation Complete!!!"
}

echo '[!] Updating...'
sudo apt-get update > install.log
echo 'Update Done!!!' >> install.log
echo
echo '[!] Installing Dependencies...'
echo '[!] Checking pip3....'
if dpkg -S `which pip3` &> /dev/null; then
	echo "[*] You have pip3..."
	echo
	echo "[!] Installing Tabulate...."
	tabulate_install
else
	echo "[!] Installing pip3..."
	pip3_install
	echo
	echo "[!] Installing Tabulate...."
	tabulate_install
fi

echo
echo "[!] Installation Logs are saved in install.log"

