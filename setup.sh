#!/bin/bash

## Bootstrap script to kick off deployment of a TRON mirror

## Process ##
# 1. Install Prerequisites
# 2. Ask For Inputs
# 3. Modify Configs To User Inputs

## FUNCTIONS ##

# Detect if apache is installed
find_apache() {
    if hash apache2 2> /dev/null || hash httpd 2> /dev/null; then
      echo -e "\e[91mIt looks like you have Apache installed.
This script is intended to be run on a fresh system
and makes use of the NGINX web server."
echo -e "\e[0m"
      read -p "Are you happy to have apache disabled? " -n 1 -r
      echo
      if [[ ! $REPLY =~ ^[Yy]$ ]]
      then
        echo Exiting
        [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
      fi
      echo "Disabling Apache."
      systemctl stop apache2 || systemctl stop httpd
      systemctl disable apache2 || systemctl disable httpd
    fi
}

# Lets make sure we are root
detect_root () {
  if [ $EUID != 0 ]; then
      echo -e "\e[91mRequesting root privileges\e[0m"
      sudo "$0" "$@"
      exit $?
  fi
}

#Find the Linux distro we are on
detect_os () {
  # Determine OS platform
  UNAME=$(uname | tr "[:upper:]" "[:lower:]")
  # If Linux, try to determine specific distribution
  if [ "$UNAME" == "linux" ]; then
      # If available, use LSB to identify distribution
      if [ -f /etc/lsb-release -o -d /etc/lsb-release.d ]; then
          export DISTRO=$(lsb_release -i | cut -d: -f2 | sed s/'^\t'//)
      # Otherwise, use release info file
      else
          export DISTRO=$(ls -d /etc/[A-Za-z]*[_-][rv]e[lr]* | grep -v "lsb" | cut -d'/' -f3 | cut -d'-' -f1 | cut -d'_' -f1)
      fi
  fi
  # For everything else (or if above failed), just use a generic identifier
  [ "$DISTRO" == "" ] && export DISTRO=$UNAME
  unset UNAME
}

install_software() {
  echo Installing prerequisite software
  # Routine for Fedora Linux
  if [[ $DISTRO == *"fedora"* ]]; then
    dnf update -y
    dnf install https://rpms.remirepo.net/fedora/remi-release-29.rpm -y
    dnf config-manager --set-enabled remi -y
    dnf install git gpg nginx curl wget git php70 php70-php-fpm certbot-nginx mailx -y
    curl https://keybase.io/vocatus/pgp_keys.asc | gpg --import
  # Routine for RHEL based distros
  elif [[ $DISTRO == *"centos"* ]] || [[ $DISTRO == *"rhel"* ]]; then
    yum update -y
    yum install curl wget git mailx -y
    yum install https://dl.fedoraproject.org/pub/epel/epel-release-latest-7.noarch.rpm -y
    wget https://rpms.remirepo.net/enterprise/remi-release-7.rpm -O /tmp/remi-release-7.rpm
    yum install /tmp/remi-release-7.rpm -y
    yum update -y
    yum install php70 php70-php-fpm nginx python2-certbot-nginx -y
    curl https://keybase.io/vocatus/pgp_keys.asc | gpg --import
  # Routine for Debian based distros
  elif [[ $DISTRO == *"debian"* ]] || [[ $DISTRO == *"ubuntu"* ]]; then
    echo "deb http://ftp.debian.org/debian stretch-backports main" >> /etc/apt/sources.list
    apt-get update
    apt-get upgrade -y
    apt-get install git php7.0-fpm php7.0 nginx curl wget mailutils git dirmngr -y
    curl https://keybase.io/vocatus/pgp_keys.asc | gpg --import
    apt-get install python-certbot-nginx -t stretch-backports -y
  else
    echo "We don't know how to install software on your distro."
    [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
  fi
}

# Function for getting the domain name as a variable
# If the user says no to the confirmation the function is called again
# until the user says yes
# If the user needs a new domain then this function also updates the DNS record
get_domain() {
  if [[ $existing_domain == "no" ]] ; then
    echo
    echo "Go to https://www.duckdns.org and create an account, then add a domain
name to your account. Record your account token as well."
    echo
    read -p "Press any key when ready to continue..." -n 1 -s
    echo
    existing_domain="duck"
  fi
  read -p "Enter your domain name: " domainname
  echo
  read -p "Your domain is $domainname, is this correct? " -n 1 -r
  if [[ ! $REPLY =~ ^[Yy]$ ]] ; then
    echo
    get_domain
  elif [[ ! $existing_domain == "duck" ]] ; then
    existing_domain="yes"
  fi
  if [[ $existing_domain == "yes" ]] ; then
    echo
    echo "Ensure this domain's DNS A record is pointing at this server."
    echo
    read -p "Press any key when ready to continue..." -n 1 -s
  elif [[ $existing_domain == "duck" ]] ; then
    echo
    echo Updating DNS record.
    echo
    read -p "Enter your account token: " token
    echo
    mkdir /root/duckdns
    echo "echo url='https://www.duckdns.org/update?domains=$domainname&token=$token&ip=' | curl -k -o /root/duckdns/duck.log -K -" > /root/duckdns/duck.sh
    chmod +x /root/duckdns/duck.sh
    crontab -u root -l > /tmp/rootcron
    echo "*/5 * * * * /root/duckdns/duck.sh >/dev/null 2>&1" >> /tmp/rootcron
    crontab -u root /tmp/rootcron
    rm /tmp/rootcron
    /root/duckdns/duck.sh
  fi
}

# This function creates a config file for NGINX
# There are a number of variables that require escaping so that NGINX can
# expand them instead of the shell
# The function also takes an argument "ssl" in the form of $1 so that it can
# be called a second time to update the config with ssl information
create_web_config() {
  web_user=$(ps -ef | egrep '(nginx)' | grep -v `whoami` | grep -v root | head -n1 | awk '{print $1}')
  mkdir -p /var/www/html/tron_mirror
  mkdir -p /etc/nginx/conf.d
  chown -R $web_user:$web_user /var/www/html/tron_mirror
cat << EOF >> /etc/nginx/conf.d/tron_mirror.conf
server {
  listen 80;
  listen [::]:80;
  server_name $domainname www.$domainname;
  root /var/www/html/tron_mirror;
  location / {
    try_files \$uri \$uri/ /index.php\$is_args\$args;
  }
  # Pass all .php files onto a php-fpm/php-fcgi server.
     location ~ [^/]\.php(/|\$) {
     fastcgi_split_path_info ^(.+?\.php)(/.*)\$;
     if (!-f \$document_root\$fastcgi_script_name) {
             return 404;
     }
     include fastcgi.conf;
     fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;
     }
}

EOF

# If ssl is passed as argument 1 then append the ssl block onto the config
if [[ $1 == "ssl" ]] ; then
  mkdir -p /etc/nginx/snippets
  openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048
cat << EOF >> /etc/nginx/snippets/ssl-$domainname.conf
ssl_certificate /etc/letsencrypt/live/$domainname/fullchain.pem;
ssl_certificate_key /etc/letsencrypt/live/$domainname/privkey.pem;
EOF

cat << EOF >> /etc/nginx/snippets/ssl-params.conf
# from https://cipherli.st/
# and https://raymii.org/s/tutorials/Strong_SSL_Security_On_nginx.html

ssl_protocols TLSv1 TLSv1.1 TLSv1.2;
ssl_prefer_server_ciphers on;
ssl_ciphers "EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH";
ssl_ecdh_curve secp384r1;
ssl_session_cache shared:SSL:10m;
ssl_session_tickets off;
ssl_stapling on;
ssl_stapling_verify on;
resolver 8.8.8.8 8.8.4.4 valid=300s;
resolver_timeout 5s;
# Disable preloading HSTS for now.  You can use the commented out header line that includes
# the "preload" directive if you understand the implications.
#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains; preload";
#add_header Strict-Transport-Security "max-age=63072000; includeSubdomains";
add_header X-Frame-Options DENY;
add_header X-Content-Type-Options nosniff;
ssl_dhparam /etc/ssl/certs/dhparam.pem;
EOF

cat << EOF >> /etc/nginx/conf.d/tron_mirror.conf
server {
  listen 443 ssl;
  listen [::]:443 ssl;
  server_name $domainame www.$domainname;
  root /var/www/html/tron_mirror;
  include snippets/ssl-$domainname.conf;
  include snippets/ssl-params.conf;
  location / {
    try_files \$uri \$uri/ /index.php\$is_args\$args;
  }
  # Pass all .php files onto a php-fpm/php-fcgi server.
     location ~ [^/]\.php(/|\$) {
     fastcgi_split_path_info ^(.+?\.php)(/.*)\$;
     if (!-f \$document_root\$fastcgi_script_name) {
             return 404;
     }
     include fastcgi.conf;
     fastcgi_pass unix:/var/run/php/php7.0-fpm.sock;
     }
}
EOF
ssl=1
fi
}

# This function writes a new tronupdate.ini
write_tron_conf() {
  echo "" > /var/www/html/tron_mirror/tronupdate.ini
  cat << EOF >> /var/www/html/tron_mirror/tronupdate.ini
  [tronupdate.ini]
  	;Set download location (usually your Tron mirror directory)
  	;If the downloadtemp is set below we will download to there then verify and move to this directory
    download_directory = /var/www/html/tron_mirror

  	;Change to true to purge all previous Tron versions when updating.
  	purge_old_versions = true

  	;symbolic link latest Tron version to "latest.exe" when updating
  	;Change to true to enable
  	symlink = true

  	;How many times do you want to attempt to re-download the file.
  	;You most likely want to leave this as-it
  	max_download_attempts = 5

  	;Duration (in seconds) to sleep before attempting the download again
  	;2 minutes is probably fine, you can tweak if needed though
  	sleep_time = 120

  	;Are we going to verify the keys of the sha256sum file to ensure authenticity?
  	;Please ensure you have gpg installed and that you import Vocatus' key: gpg --recv-keys 82A211A2
  	;I STRONGLY RECCOMEND YOU LEAVE THIS ON - In the event a malicious version of Tron make it
  	;to the official repo this will ensure it doesn't propogate to your mirror.
  	check_gpg = true

  	;Send email alert on various failure events - your server must have an email server configured (sendmail, postfix, etc)
  	;Set to true to enable (also enter your email addresses below)
  	send_email = true

  	;Send email alert when updating the mirror?  As sbove must have an email server configured
  	;Set to true to enable
  	update_email = true

  	;The email address we are sending from
  	email_from = tron@$domainname

  	;The email address we are sending to
  	email_to = $email

  	;Enable logging of script actions to a file
  	;Set true to enable and specify the log location below
  	enable_logging = true

  	;Do you want to overwrite the log each run?
  	;Set true to overwrite and false to keep existing entries
  	overwrite_log = true

  	;The location of the log file
  	;If you're on shared hosting this will need changed
  	log_location = /var/log/tronupdate.log

  	;IF YOU ENABLE LOGGING I SUGGEST YOU CREATE A LOGROTATE FILE FOR TRON
  	;/var/log/tronupdate.log {
  	;	missingok
  	;	monthly
  	;	notifempty
  	;	compress
  	;}

  	;Set true to enable downloading to a temp directory
  	;Once the sha256sum is verified the file will be moved to the proper directory
  	;Be sure to specify the temp directory below
  	;NOTE: We don't worry about the shasum files and download straight to the specified directory
  	download_temp = true

  	;Temp directory to download the file to for verification
  	temp_dir=/tmp/tron

  	;The URL for the official repo
  	;You will most likely want to keep this as it is.
  	repo_dir = https://bmrf.org/repos/tron

  	;The URL to the signature file
  	;You will most likely want to keep this as it is.
  	sha256sumasc = https://bmrf.org/repos/tron/sha256sums.txt.asc

  	;The URL to the sha256sum file
  	;You will most likely want to keep this as it is.
  	sha256sumsurl = https://bmrf.org/repos/tron/sha256sums.txt
EOF
}

## END FUNCTIONS ##


# Check if we are using BASH
if [ ! "$BASH_VERSION" ] ; then
    echo "Please do not specify a shell to run this script ($0), just execute it directly" 1>&2
    exit 1
fi
echo
detect_root
echo
echo '
 ___________ _____ _   _
|_   _| ___ \  _  | \ | |
  | | | |_/ / | | |  \| |
  | | |    /| | | | . ` |
  | | | |\ \\ \_/ / |\  |
  \_/ \_| \_|\___/\_| \_/
   Mirror Install Script
'
echo
echo This script will modify your system and is intended to be used on a fresh install.
echo Deployment of TRON mirror about to commence.
read -p "Are you ready to begin? " -n 1 -r
echo
if [[ ! $REPLY =~ ^[Yy]$ ]] ; then
  echo Exiting
  [[ "$0" = "$BASH_SOURCE" ]] && exit 1 || return 1
fi
echo
find_apache
echo
detect_os
echo
install_software
echo
read -p "Do you already have a domain to use for your mirror? " -n 1 -r
if [[ ! $REPLY =~ ^[Yy]$ ]] ; then
  existing_domain="no"
fi
echo
get_domain
echo
create_web_config
systemctl restart nginx
echo
read -p "Enter your email address for mirror update alerts: " email
echo
read -p "Would you like to enable HTTPS (Account will be created with previously entered email address)? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] ; then
  # Generate a certificate for ssl use
  echo
  certbot --nginx certonly --email $email --agree-tos
  create_web_config ssl
fi
systemctl restart nginx
systemctl enable nginx
# Pull the fancy mirror git repo into the web root
git clone https://github.com/danodemano/Tron-Mirror.git /var/www/html/tron_mirror
# Backup the original tronupdate.ini
cp /var/www/html/tron_mirror/tronupdate.ini /var/www/html/tron_mirror/tronupdate.ini.bak
# Edit the tronupdate.ini file
write_tron_conf
# Create a cron job for checking if TRON is up to date
echo "5 * * * * root /var/www/html/tron_mirror/tronupdate.sh  > /dev/null 2>&1" > /etc/cron.d/tronmirror
echo
read -p "Shall we pull the initial version of TRON now? " -n 1 -r
echo
if [[ $REPLY =~ ^[Yy]$ ]] ; then
  echo Getting initial TRON version
  chmod +x /var/www/html/tron_mirror/tronupdate.sh
  echo
  /var/www/html/tron_mirror/tronupdate.sh
  echo
  echo Calling script twice to ensure latest hash
  /var/www/html/tron_mirror/tronupdate.sh
fi
echo
echo
echo -e "\e[92mAll finished!"
echo
if [[ $ssl == 1 ]] ; then
  echo -e "\e[0mVisit https://$domainname to view your new mirror"
  echo
else
  echo -e "\e[0mVisit http://$domainname to view your new mirror"
  echo
fi
