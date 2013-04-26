#!/bin/bash


##############################################
#
# LazyKali by Reaperz73
# Just made this for when I feel lazy
# Installs quite a few extras to a Fresh Kali
#
##############################################
clear
version="20130426"
#some variables
DEFAULT_ROUTE=$(ip route show default | awk '/default/ {print $3}')
IFACE=$(ip route show | awk '(NR == 2) {print $3}')
JAVA_VERSION=`java -version 2>&1 |awk 'NR==1{ gsub(/"/,""); print $3 }'`
MYIP=$(ip route show | awk '(NR == 2) {print $9}')

if [ $UID -ne 0 ]; then
    echo -e "\033[31This program must be run as root.This will probably fail.\033[m"
    sleep 3
    fi

###### Install script if not installed
if [ ! -e "/usr/bin/lazykali" ];then
	echo "Script is not installed. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		cp -v $0 /usr/bin/lazykali
		chmod +x /usr/bin/lazykali
		#rm $0
		echo "Script should now be installed. Launching it !"
		sleep 3
		lazykali
		exit 1
	else
		echo "Ok, not installing then !"
	fi
else
	echo "Script is installed"
	sleep 1
fi
### End of install process

### Check for updates !
if [[ "$silent" = "1" ]];then
	echo "Not checking for a new version : silent mode."
else
	changelog=$(curl --silent -q http://yourgeekonthego.com/scripts/lazykali/changelog)
	last_version=$(curl --silent -q http://yourgeekonthego.com/scripts/lazykali/version) #store last version number to variable
	if [[ $last_version > $version ]];then # Comparing to current version
		echo -e "You are running version \033[31m$version\033[m, do you want to update to \033[32m$last_version\033[m? (Y/N)
Last changes are :
$changelog"
		read update
		if [[ $update = Y || $update = y ]];then
			echo "[+] Updating script..."
			wget -q http://yourgeekonthego.com/scripts/lazykali/lazykali.sh -O $0
			chmod +x $0
			echo "[-] Script updated !"
			if [[ $0 != '/usr/bin/yamas' && $ask_for_install = 'y' ]];then
				echo -e "Do you want to install it so that you can launch it with \"yamas\" ?"
				read install
				if [[ $install = Y || $install = y ]];then #do not proceed to install if using installed version : updating it already "installed" it over.
					cp $0 /usr/bin/lazykali
					chmod +x /usr/bin/lazykali
					echo "Script should now be installed, launching yamas !"
					sleep 3
					lazykali
					exit 1
				else
					echo "Ok, continuing with updated version..."
					sleep 3
					$0
					exit 1
				fi
			fi
		
		sleep 2
		$0
		exit 1
		else
			echo "Ok, continuing with current version..."
		fi
	else
		echo "No update available"
	fi
fi
### End of update process

#### pause function
function pause(){
   read -sn 1 -p "Press any key to continue..."
}

#### credits
function credits {
clear
echo -e "
\033[31m#######################################################\033[m
                       Credits To
\033[31m#######################################################\033[m"
echo -e "\033[36m
Special thanks to:
Offensive Security for the awesome OS
http://www.offensive-security.com/
http://www.kali.org/

ComaX for Yamas
http://comax.fr/yamas.php

Brav0hax for Easy-Creds
https://github.com/brav0hax/easy-creds

VulpiArgenti for PwnStar
http://code.google.com/p/pwn-star/

Simple-Ducky
http://code.google.com/p/simple-ducky-payload-generator/

0sm0s1z for Subterfuge
http://code.google.com/p/subterfuge/

and anyone else I may have missed.

\033[m"
}

#### Screwup function
function screwup {
	echo "You Screwed up somewhere, try again."
	pause 
	clear
}


######## Update Kali
function updatekali {
clear
echo -e "
\033[31m#######################################################\033[m
                Let's Update Kali
\033[31m#######################################################\033[m"
select menusel in "Update Kali" "Update and Clean Kali" "Back to Main"; do
case $menusel in
	"Update Kali")
		clear
		echo -e "\033[32mUpdating Kali\033[m"
		apt-get update && apt-get -y dist-upgrade 
		echo -e "\033[32mDone updating kali\033[m"
		pause
		clear ;;
	
	"Update and Clean Kali")
		clear
		echo -e "\033[32mUpdating and Cleaning Kali\033[m"
		apt-get update && apt-get -y dist-upgrade && apt-get autoremove -y && apt-get -y autoclean
		echo -e "\033[32mDone updating and cleaning kali\033[m" ;;
		
	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		updatekali ;;

esac

break

done
}

##### Metasploit Services
function metasploitservices {
clear
echo -e "
\033[31m#######################################################\033[m
                Metasploit Services
\033[31m#######################################################\033[m"
select menusel in "Start Metasploit Services" "Stop Metasploit Services" "Restart Metasploit Services" "Autostart Metasploit Services" "Back to Main"; do
case $menusel in
	"Start Metasploit Services")
		echo -e "\033[32mStarting Metasploit Services..\033[m"
		service postgresql start && service metasploit start
		echo -e "\033[32mNow Open a new Terminal and launch msfconsole\033[m"
		pause ;;
	
	"Stop Metasploit Services")
		echo -e "\033[32mStoping Metasploit Services..\033[m"
		service postgresql stop && service metasploit stop
		pause ;;
		
	"Restart Metasploit Services")
		echo -e "\033[32mRestarting Metasploit Services..\033[m"
		service postgresql restart && service metasploit restart
		pause ;;
		
	"Autostart Metasploit Services")
		echo -e "\033[32mSetting Metasploit Services to start on boot..\033[m"
		update-rc.d postgresql enable && update-rc.d metasploit enable
		pause ;;

	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		metasploitservices ;;		
		
esac

break

done
}

######## Open Vas Services
function OpenVas {
clear
echo -e "
\033[31m#######################################################\033[m
                  OpenVas Services
\033[31m#######################################################\033[m"
select menusel in "Start OpenVas Services" "Stop OpenVas Services" "Back to Main"; do
case $menusel in
	"Start OpenVas Services")
		openvasstart
		pause 
		OpenVas;;
	
	"Stop OpenVas Services")
		openvasstop
		pause
		OpenVas ;;

	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		OpenVas ;;
	
		
esac

break

done
}

######## Sniffing and spoofing menu
function sniffspoof {
clear
echo -e "
\033[31m#######################################################\033[m
                Sniffing/Spoofing/MITM
\033[31m#######################################################\033[m"
select menusel in "Yamas" "EasyCreds" "PwnStar" "Subterfuge" "Ghost-Phisher" "Hamster&Ferret" "Back to Main"; do
case $menusel in
	"Yamas")
		installyamas
		pause
		sniffspoof ;;
		
	"EasyCreds")
		easycreds
		pause
		sniffspoof ;;
	
	"PwnStar")
		pwnstar
		pause
		sniffspoof ;;
		
	"Subterfuge")
		subterfuge
		pause
		sniffspoof ;;
		
	"Ghost-Phisher")
		ghostphisher
		pause
		sniffspoof ;;
		
	"Hamster&Ferret")
		hamfer
		pause
		sniffspoof ;;

	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		sniffspoof ;;
	
		
esac

break

done
}

######## Sniffing and spoofing menu
function payloadgen {
clear
echo -e "
\033[31m#######################################################\033[m
                Sniffing/Spoofing/MITM
\033[31m#######################################################\033[m"
select menusel in "Simple-Ducky" "Back to Main"; do
case $menusel in
	"Simple-Ducky")
		simpleducky
		pause
		payloadgen ;;
		
	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		sniffspoof ;;
	
		
esac

break

done
}

function bleedingedge {
		#Add bleeding edge repository
		out=`grep  "kali-bleeding-edge" /etc/apt/sources.list` &>/dev/null
		if [[ "$out" !=  *kali-bleeding-edge* ]]; then &>/dev/null
		echo "Bleeding Edge Repo is not installed. Do you want to install it ? (Y/N)"
		read install
			if [[ $install = Y || $install = y ]] ; then
				echo -e "\033[31m====== Adding Bleeding Edge repo and updating ======\033[m"
				echo "" >> /etc/apt/sources.list
				echo '# Bleeding Edge ' >> /etc/apt/sources.list
				echo 'deb http://repo.kali.org/kali kali-bleeding-edge main' >> /etc/apt/sources.list
				apt-get update
				apt-get -y upgrade
			else
				echo "Ok, not installing then !"
			fi
		else
			echo "Bleeding Edge Repo already there"
			sleep 1
		fi
}

function installangryip {
if [ ! -e "/usr/bin/ipscan" ];then
			echo "AngryIp Scanner is not installed. Do you want to install it ? (Y/N)"
			read install
			if [[ $install = Y || $install = y ]] ; then	
				echo -e"\033[31m====== Installing Angry IP Scanner ======\033[m"
				# Install angry-IP-scanner
				cd /root/ &>/dev/null
				if [ $(uname -m) == "x86_64" ] ; then
					#64 bit system
					wget -N http://sourceforge.net/projects/ipscan/files/ipscan3-binary/3.2/ipscan_3.2_amd64.deb &>/dev/null
					dpkg -i ipscan_3.2_amd64.deb &>/dev/null
				else
					#32 bit system
					wget -N http://sourceforge.net/projects/ipscan/files/ipscan3-binary/3.2/ipscan_3.2_i386.deb &>/dev/null
					dpkg -i ipscan_3.2_i386.deb &>/dev/null
				fi
				pause
				extras
				exit 1
			else
				echo "Ok, not installing then !"
			fi
		else
			echo "AngryIP Scanner is installed."
		fi
}

function installterminator {
	echo "This will install Terminator. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		apt-get -y install terminator 
	else
		echo "Ok,maybe later !"
	fi
}

function installxchat {
	echo "This will install Xchat. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		apt-get -y install xchat 
	else
		echo "Ok,maybe later !"
	fi
}

function installnautilusopenterm {
	echo "This will install Nautilus Open Terminal. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		apt-get -y install nautilus-open-terminal
	else
		echo "Ok,maybe later !"
	fi
}

function installunicornscan {
	if [ ! -f /usr/local/bin/unicornscan ]; then
		echo "This will install Unicornscan. Do you want to install it ? (Y/N)"
		read install
			if [[ $install = Y || $install = y ]] ; then
				echo -e"\033[31m====== Installing Flex ======\033[m"
				apt-get install flex &>/dev/null
				echo -e"\033[32m====== Done Installing Flex ======\033[m"
				echo -e"\033[31m====== Installing Unicornscan ======\033[m"
				cd /root/ &>/dev/null
				wget -N http://unicornscan.org/releases/unicornscan-0.4.7-2.tar.bz2 
				bzip2 -cd unicornscan-0.4.7-2.tar.bz2 | tar xf - 
				cd unicornscan-0.4.7/ 
				./configure CFLAGS=-D_GNU_SOURCE && make && make install
				cd /root/ &>/dev/null
				echo -e "\033[32m====== All Done ======\033[m"
				echo "Launch a new terminal and enter unicornscan to run."
			else
				echo "Ok,maybe later !"
			fi
		else
			echo "Unicornscan is installed."
			echo "Launch a new terminal and enter unicornscan to run."
			
		fi	
}

function installyamas {
	if [ ! -f /usr/bin/yamas ]; then
		echo "Yamas is not installed. Do you want to install it ? (Y/N)"
		read install
		if [[ $install = Y || $install = y ]] ; then
			cd /tmp
			wget http://comax.fr/yamas/bt5/yamas.sh
			cp yamas.sh /usr/bin/yamas
			chmod +x /usr/bin/yamas
			rm yamas.sh
			cd
			echo "Script should now be installed. Launching it !"
			sleep 3
			gnome-terminal -t "Yamas" -x bash yamas 2>/dev/null & sleep 2
			exit 1
		else
			echo "Ok, not installing then !"
		fi
	else
		echo "Script is installed"
		gnome-terminal -t "Yamas" -x bash yamas 2>/dev/null & sleep 2
		sleep 1
	fi		
}

function easycreds {
	if [ ! -f /usr/bin/easy-creds ]; then
		echo "This will install Easy-Creds. Do you want to install it ? (Y/N)"
		read install
			if [[ $install = Y || $install = y ]] ; then
				echo -e"\033[31m====== Installing Depends ======\033[m"
				apt-get -y install screen hostapd dsniff dhcp3-server ipcalc aircrack-ng
				echo -e"\033[32m====== Done Installing Depends ======\033[m"
				echo -e"\033[31m====== Installing Easy-Creds ======\033[m"
				git clone git://github.com/brav0hax/easy-creds.git /opt/easy-creds
				ln -s /opt/easy-creds/easy-creds.sh  /usr/bin/easy-creds.sh
				cd /root/ &>/dev/null
				echo -e "\033[32===== All Done ======\033[m"
				echo "Launching easy-creds in new window !"
				gnome-terminal -t "Easy-Creds" -e easy-creds 2>/dev/null & sleep 2				
			else
				echo "Ok,maybe later !"
			fi
		else
			echo "Easy-Creds is installed."
			echo "Launching easy-creds in new window !"
			gnome-terminal -t "Easy-Creds" -e easy-creds 2>/dev/null & sleep 2	
		fi	
}

######### PwnStar
function pwnstar {
		if [ ! -e "/opt/PwnSTAR_0.9/PwnSTAR_0.9" ];then
			echo "PwnStar is not installed. Do you want to install it ? (Y/N)"
			read install
			if [[ $install = Y || $install = y ]] ; then
				mkdir /opt/PwnSTAR_0.9
				cd /opt/PwnSTAR_0.9
				wget http://pwn-star.googlecode.com/files/PwnSTAR_0.9.tgz
				tar -zxvf PwnSTAR_0.9.tgz 
				mv hotspot_3 /var/www/ && mv portal_hotspot /var/www/ && mv portal_pdf /var/www/ && mv portal_simple /var/www/
				#rm $0
				echo "PwnStar should now be installed. Launching it !"
				sleep 3
				gnome-terminal -t "PwnStar" -e /opt/PwnSTAR_0.9/PwnSTAR_0.9 2>/dev/null & sleep 2
				pause
				sniffspoof
				exit 1
			else
				echo "Ok, not installing then !"
			fi
		else
			echo "PwnStar is installed, Launching it now!"
			sleep 1
			gnome-terminal -t "PwnStar" -e /opt/PwnSTAR_0.9/PwnSTAR_0.9 2>/dev/null & sleep 2
		fi 
}

### Hunting with rodents hamster and ferret
function hamfer {
		if [ ! -e "/usr/share/hamster-sidejack/ferret" ];then
			echo -e "\033[31m[+] Creating link /usr/share/hamster-sidejack/ferret\033[m"
			echo "we need this to avoid file not found error"
			ln -s /usr/bin/ferret /usr/share/hamster-sidejack/ferret
			hamfer			
		else
			echo -e "\033[31m[+] Starting Sidejacking with Hamster & Ferret.\033[m"
			echo "1" > /proc/sys/net/ipv4/ip_forward
			iptables -t nat -A PREROUTING -p tcp --destination-port 80 -j REDIRECT --to-port 1000
			sslstrip -f -a -k -l 1000 -w /root/out.txt &
			sleep 4
			xterm -geometry 90x3-1-1 -T "arpspoof" -e arpspoof -i $IFACE $DEFAULT_ROUTE &
			sleep 2
			#xterm -e /usr/share/hamster-sidejack/ferret -i $IFACE 2>/dev/null & sleep 2
			cd /usr/share/hamster-sidejack
			xterm -e ./hamster 2>/dev/null & sleep 2 
			echo -e "\n\033[31m[+] Attack is running\033[m.\nSet browser proxy to 127.0.0.1:1234\nIn Browser go to http://hamster\nPress (q) to stop"
			cd
			while read -n1 char
			do
				case $char in
				q)
				break
				;;
			
				* )
					echo -ne "\nInvalid character '$char' entered. Press (q) to quit."
				esac
			done
			echo -e "\033[31m\n[+] Killing processes and resetting iptable.\033[m"
			killall sslstrip
			killall arpspoof
			killall ferret
			killall hamster
			echo "0" > /proc/sys/net/ipv4/ip_forward
			iptables --flush
			iptables --table nat --flush
			iptables --delete-chain
			iptables --table nat --delete-chain
			echo -e "\033[32m[-] Clean up successful !\033[m"
	
		fi	

}

#####simple-ducky
function installsimpleducky {
	if [ ! -e "/usr/bin/simple-ducky" ];then
			echo "Simple-Ducky is not installed. Do you want to install it ? (Y/N)"
			read install
			if [[ $install = Y || $install = y ]] ; then
				wget https://code.google.com/p/simple-ducky-payload-generator/downloads/detail?name=install_v1.0.8.sh&can=2&q=
				chmod +x install_v1.0.8.sh
				./install_v1.0.8.sh
				rm install_v1.0.8.sh
				echo -e "\e[1;34mDone! Be sure to run Option's 5 and 6 prior to generating any payloads.\e[0m"
				pause
				extras				
			else
				echo "Ok,maybe later !"
			fi
		else
			echo "Simple-Ducky is installed."
			echo "Launch a new terminal and enter simple-ducky to run."			
		fi	
}

#################################################################################
# JAVA JDK Update
#################################################################################
function installjava {
	echo -e "\e[1;31mThis option will update your JDK version to jdk1.7.0\e[0m"
	echo -e "\e[1;31mUse this only if java not installed or your version is older than this one!\e[0m"
	echo -e "\e[1;31mYour current Version is : $JAVA_VERSION\e[0m"
	echo "Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
			read -p "Are you using a 32bit or 64bit operating system [ENTER: 32 or 64]? " operatingsys
			if [ "$operatingsys" == "32" ]; then 
				echo -e "\e[1;31m[+] Downloading and Updating to jdk1.7.0\e[0m"
				echo -e ""
				wget --no-cookies --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com" "http://download.oracle.com/otn-pub/java/jdk/7/jdk-7-linux-i586.tar.gz"
				tar zxvf jdk-7-linux-i586.tar.gz
				mv jdk1.7.0 /usr/lib/jvm
				update-alternatives --install /usr/bin/java java /usr/lib/jvm/jdk1.7.0/jre/bin/java 2
				echo -e "\e[1;34mWhen prompted, select option 2\e[0m"
				sleep 2
				echo -e ""
				update-alternatives --config java
				rm jdk-7-linux-i586.tar.gz
				echo -e ""
				echo -e "\e[1;34mYour new JDk version is...\e[0m"
				echo ""
				java -version
				sleep 3
				echo ""
			else
				echo -e "\e[1;31m[+] Downloading and Updating to jdk1.7.0\e[0m"
				echo -e ""
				wget --no-cookies --header "Cookie: gpw_e24=http%3A%2F%2Fwww.oracle.com" "http://download.oracle.com/otn-pub/java/jdk/7u17-b02/jdk-7u17-linux-x64.tar.gz"
				tar zxvf jdk-7u17-linux-x64.tar.gz
				mv jdk1.7.0_17/ /usr/lib/jvm
				update-alternatives --install /usr/bin/java java /usr/lib/jvm/jdk1.7.0_17/jre/bin/java 2
				echo -e "\e[1;34mWhen prompted, select option 2\e[0m"
				sleep 2
				echo -e ""
				update-alternatives --config java
				rm jdk-7u17-linux-x64.tar.gz
				echo -e ""
				echo -e "\e[1;34mYour new JDk version is...\e[0m"
				echo ""
				java -version
				sleep 3
				echo ""
			fi
		else
			echo "Ok,maybe later !"
		fi

}

function simpleducky {
	if [ ! -e "/usr/bin/simple-ducky" ];then
			echo "Simple-Ducky is not installed. Do you want to install it ? (Y/N)"
			read install
			if [[ $install = Y || $install = y ]] ; then
				installsimpleducky
				payloadgen
				exit 1
			else
				echo "Ok, not installing then !"
			fi
		else
			echo -e "\e[31m[+] Launching Simple-Ducky now!\nBe sure to run Option's 5 and 6 prior to generating any payloads.\e[0m"
			sleep 1
			gnome-terminal -t "Simple-Ducky" -e "bash simple-ducky" 2>/dev/null & sleep 2
		fi 
}

#####openvasstart
function openvasstart {
# style variables
execstyle="[\e[01;32mx\e[00m]" # execute msgs style
warnstyle="[\e[01;31m!\e[00m]" # warning msgs stylee
infostyle="[\e[01;34mi\e[00m]" # informational msgs style

#fun little banner
clear
echo -e "\e[01;32m 
####### ######  ####### #     # #     #    #     #####  
#     # #     # #       ##    # #     #   # #   #     # 
#     # #     # #       # #   # #     #  #   #  #       
#     # ######  #####   #  #  # #     # #     #  #####  
#     # #       #       #   # #  #   #  #######       # 
#     # #       #       #    ##   # #   #     # #     # 
####### #       ####### #     #    #    #     #  #####  
                                                        
\e[0m"
echo -e "\e[1;1m   ..----=====*****(( Startup Script ))*******=====----..\e[0m"
echo -e "\e[31m *************************************************************\e[0m"
echo -e "\e[31m *                                                           *\e[0m"
echo -e "\e[31m *              \e[1;37mStarting All OpenVas Services \e[0;31m               *\e[0m"
echo -e "\e[31m *                      By Reaperz73                         *\e[0m"
echo -e "\e[31m *************************************************************\e[0m"

echo
echo -e "\e[31mKilling all Openvas for fresh start.\e[0m"
#kill openvas scanner
echo -e "$execstyle Checking OpenVas Scanner is running..."
ps -ef | grep -v grep | grep openvassd
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Scanner not running!" 
 else
	echo -e "$execstyle Stopping OpenVas Scanner..."
	killall openvassd
fi

#kill openvas administrator
echo -e "$execstyle Checking if OpenVas Administrator is running..."
ps -ef | grep -v grep | grep openvasad
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Administrator not running!" 
 else
	echo -e "$execstyle Stopping OpenVas Administrator..."
	killall openvasad
fi

#kill openvas manager
echo -e "$execstyle Checking if OpenVas Manager is running..."
ps -ef | grep -v grep | grep openvasmd
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Manager not running!" 
 else
	echo -e "$execstyle Stopping OpenVas Manager..."
	killall openvasmd
fi

#kill Greenbone Security Assistant
echo -e "$execstyle Checking if Greenbone Security Assistant is running..."
ps -ef | grep -v grep | grep gsad
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle Greenbone Security Assistant not running!" 
 else
	echo -e "$execstyle Stopping Greenbone Security Assistant..."
	killall gsad
fi

#### all done! now start services
echo
echo -e "\033[31mAll Done!! :\033[m
Now starting OpenVas services..."

echo -e "\033[31mSyncing updates.......\033[m
This may take a while!!!!"
openvas-nvt-sync
echo ok!

echo -e "\e[31mStarting OpenVas Scanner.\e[0m"
openvassd
echo ok!

echo -e "\033[31mRebuilding database......\033[m
This may take a while!!!!"
openvasmd --migrate
openvasmd --rebuild
echo ok!

echo -e "\e[31mStarting OpenVas Manager.\e[0m"
openvasmd -p 9390 -a 127.0.0.1
echo ok!

echo -e "\e[31mStarting OpenVas Administrator.\e[0m"
openvasad -a 127.0.0.1 -p 9393
echo ok!

echo -e "\e[31mStarting Greenbone Security Assistant.\e[0m"
gsad --http-only --listen=127.0.0.1 -p 9392
echo ok! All should be good!

#is it up openvas scanner
echo -e "$execstyle Checking if OpenVas Scanner is running..."
ps -ef | grep -v grep | grep openvassd
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Scanner not running!" 
 else
	echo -e "$infostyle OpenVas Scanner is running!!"
fi

#is it up openvas administrator
echo -e "$execstyle Checking if OpenVas Administrator is running..."
ps -ef | grep -v grep | grep openvasad
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Administrator not running!" 
 else
	echo -e "$infostyle OpenVas Administrator is running!!"
fi

#is it up openvas manager
echo -e "$execstyle Checking if OpenVas Manager is running..."
ps -ef | grep -v grep | grep openvasmd
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Manager not running!" 
 else
	echo -e "$infostyle OpenVas Manager is running!!"
fi

#is it up Greenbone Security Assistant
echo -e "$execstyle Checking if Greenbone Security Assistant is running..."
ps -ef | grep -v grep | grep gsad
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle Greenbone Security Assistant not running!" 
 else
	echo -e "$infostyle Greenbone Security Assistant is running"
fi

#### all done!
echo
echo -e "\033[01;32mOK!!\033[m"
echo -e "\033[31mAll Done!! :) \033[m
OpenVas is running!! Open browser to 127.0.0.1:9392 or open Green Bone Security Desktop."
}

########openvasstop
function openvasstop {
# style variables
execstyle="[\e[01;32mx\e[00m]" # execute msgs style
warnstyle="[\e[01;31m!\e[00m]" # warning msgs style
infostyle="[\e[01;34mi\e[00m]" # informational msgs style

#fun little banner
clear
echo -e "\e[01;32m
####### ######  ####### #     # #     #    #     #####  
#     # #     # #       ##    # #     #   # #   #     # 
#     # #     # #       # #   # #     #  #   #  #       
#     # ######  #####   #  #  # #     # #     #  #####  
#     # #       #       #   # #  #   #  #######       # 
#     # #       #       #    ##   # #   #     # #     # 
####### #       ####### #     #    #    #     #  #####  
                                                        
\e[0m"
echo -e "\e[1;1m   ..----=====*****(( Shutdown Script ))*******=====----..\e[0m"
echo -e "\e[31m *************************************************************\e[0m"
echo -e "\e[31m *                                                           *\e[0m"
echo -e "\e[31m *              \e[1;37mStopping All OpenVas Services \e[0;31m               *\e[0m"
echo -e "\e[31m *                                                           *\e[0m"
echo -e "\e[31m *************************************************************\e[0m"

#kill openvas scanner
echo -e "$execstyle Checking OpenVas Scanner is running..."
ps -ef | grep -v grep | grep openvassd
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Scanner not running!" 
 else
	echo -e "$execstyle Stopping OpenVas Scanner..."
	killall openvassd
	echo -e "$infostyle OpenVas Scanner is dead!!"
fi

#kill openvas administrator
echo -e "$execstyle Checking if OpenVas Administrator is running..."
ps -ef | grep -v grep | grep openvasad
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Administrator not running!" 
 else
	echo -e "$execstyle Stopping OpenVas Administrator..."
	killall openvasad
	echo -e "$infostyle OpenVas Administrator is dead!!"
fi

#kill openvas manager
echo -e "$execstyle Checking if OpenVas Manager is running..."
ps -ef | grep -v grep | grep openvasmd
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle OpenVas Manager not running!" 
 else
	echo -e "$execstyle Stopping OpenVas Manager..."
	killall openvasmd
	echo -e "$infostyle OpenVas Manager is dead!!"
fi

#kill Greenbone Security Assistant
echo -e "$execstyle Checking if Greenbone Security Assistant is running..."
ps -ef | grep -v grep | grep gsad
if [ $? -eq 1 ]
 then
	echo -e "$warnstyle Greenbone Security Assistant not running!" 
 else
	echo -e "$execstyle Stopping Greenbone Security Assistant..."
	killall gsad
	echo -e "$infostyle Greenbone Security Assistant is dead!!"

fi

#### all done!
echo
echo -e "\033[01;32m All Done!! :) \033[m"
}

#### Install Subterfuge
function installsubterfuge {
	echo "This will install Subterfuge. Do you want to install it ? (Y/N)"
	read install
	if [[ $install = Y || $install = y ]] ; then
		echo -e "\e[31m[+] Installing Subterfuge now!\e[0m"
		cd /tmp
		wget http://subterfuge.googlecode.com/files/SubterfugePublicBeta5.0.tar.gz
		tar zxvf SubterfugePublicBeta5.0.tar.gz
		cd subterfuge
		python install.py
		cd ../
		rm -rf subterfuge/
		rm SubterfugePublicBeta5.0.tar.gz
		echo -e "\e[32m[-] Done Installing Subterfuge!\e[0m"		
	else
		echo "Ok,maybe later !"
	fi
}
##### Subterfuge
function subterfuge {
	if [ ! -f /usr/local/bin/unicornscan ]; then
			installsubterfuge
		else
			echo "Subterfuge is installed."
			echo -e "\e[31m[+] Launching Subterfuge now!\e[0m"
			echo "leave the window that opens open until done using."
			gnome-terminal -t "Subterfuge" -e subterfuge 2>/dev/null & sleep 2			
		fi	
}

##### Ghost-Phisher
function ghostphisher {
	if [ ! -f /opt/Ghost-Phisher/ghost.py ]; then
			installghostphisher
		else
			echo "Ghost-Phisher is installed."
			echo -e "\e[31m[+] Launching Ghost-Phisher now!\e[0m"
			python /opt/Ghost-Phisher/ghost.py 2>/dev/null & sleep 2			
		fi	
}

######## Install Ghost-Phisher
function installghostphisher {
	echo "This will install Ghost-Phisher. Do you want to install it ? (Y/N)"
	echo "Ghost-Phisher may be buggy right now with Kali. I am sure it will be fixed soon."
	read install
	if [[ $install = Y || $install = y ]] ; then
		echo -e "\e[31m[+] Installing Ghost-Phisher now!\e[0m"
		cd /tmp
		wget http://ghost-phisher.googlecode.com/files/Ghost-Phisher_1.5_all.deb
		dpkg -i Ghost-Phisher_1.5_all.deb
		rm Ghost-Phisher_1.5_all.deb
		echo -e "\e[32m[-] Done Installing Subterfuge!\e[0m"		
	else
		echo "Ok,maybe later !"
	fi
	
	
}
	

######### Install extras
function extras {
clear
echo -e "
\033[31m#######################################################\033[m
                Install Extras
\033[31m#######################################################\033[m"

select menusel in "Bleeding Edge Repos" "AngryIP Scanner" "Terminator" "Xchat" "Unicornscan" "Nautilus Open Terminal" "Simple-Ducky" "Subterfuge" "Ghost-Phisher" "Java" "Install All" "Back to Main"; do
case $menusel in
	"Bleeding Edge Repos")
		bleedingedge
		pause 
		extras;;
	
	"AngryIP Scanner")
		installangryip
		pause
		extras  ;;
		
	"Terminator")
		installterminator
		pause
		extras  ;;

	"Xchat")
		installxchat
		pause
		extras  ;;
			
	"Unicornscan")
		installunicornscan
		pause
		extras ;;
		
	"Nautilus Open Terminal")
		installnautilusopenterm
		pause
		extras ;;
		
	"Simple-Ducky")
		installsimpleducky
		pause
		extras ;;
		
	"Subterfuge")
		installsubterfuge
		pause
		extras ;;
		
	"Ghost-Phisher")
		installghostphisher
		pause
		extras ;;
		
	"Java")
		installjava
		pause
		extras ;;
		
	"Install All")
		echo -e "\e[36mJava is install seperately choose it from the extra's menu\e[0m"
		echo -e "\e[31m[+] Installing Extra's\e[0m"
		bleedingedge
		installangryip
		installterminator
		installxchat
		installunicornscan
		installnautilusopenterm
		installsimpleducky
		installsubterfuge
		installghostphisher
		echo -e "\e[32m[-] Done Installing Extra's\e[0m"
		pause
		extras ;;
		

	"Back to Main")
		clear
		mainmenu ;;
		
	*)
		screwup
		extras ;;
	
		
esac

break

done
}
########################################################
##             Main Menu Section
########################################################
function mainmenu {
echo -e "
\033[31m################################################################\033[m
\033[1;36m
.____                           ____  __.      .__  .__ 
|    |   _____  ___________.__.|    |/ _|____  |  | |__|
|    |   \__  \ \___   <   |  ||      < \__  \ |  | |  |
|    |___ / __ \_/    / \___  ||    |  \ / __ \|  |_|  |
|_______ (____  /_____ \/ ____||____|__ (____  /____/__|
        \/    \/      \/\/             \/    \/         

\033[m                                        
                   Script by Reaperz73
                    version : \033[32m$version\033[m
Script Location : \033[32m$0\033[m
Connection Info :-----------------------------------------------
  Gateway: \033[32m$DEFAULT_ROUTE\033[m Interface: \033[32m$IFACE\033[m My LAN Ip: \033[32m$MYIP\033[m
\033[31m################################################################\033[m"

select menusel in "Update Kali" "Metasploit Services" "OpenVas Services" "Sniffing/Spoofing" "Install Extras" "Payload Gen" "HELP!" "Credits" "EXIT PROGRAM"; do
case $menusel in
	"Update Kali")
		updatekali
		clear ;;
	
	"Metasploit Services")
		metasploitservices
		clear ;;
			
	"OpenVas Services")
		OpenVas
		clear ;;
	
	"Sniffing/Spoofing")
		sniffspoof
		clear ;;
	
	"Install Extras")
		extras 
		clear ;;

	"Payload Gen")
		payloadgen
		clear ;;
	
	"HELP!")
		echo "What do you need help for, seems pretty simple!"
		pause
		clear ;;
		
	"Credits")
		credits
		pause
		clear ;;

	"EXIT PROGRAM")
		clear && exit 0 ;;
		
	* )
		screwup
		clear ;;
esac

break

done
}

while true; do mainmenu; done
