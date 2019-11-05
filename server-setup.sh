#!/bin/bash

#------------------------------------------------------------------------------------
# Update repos and server - y
#------------------------------------------------------------------------------------

add-apt-repository universe
apt -y install software-properties-common
add-apt-repository -y ppa:ondrej/php
apt-get -y update
apt-get -y upgrade
apt -y autoremove

#------------------------------------------------------------------------------------
# Config firewall - y
#------------------------------------------------------------------------------------

ufw default deny incoming
ufw default allow outgoing
ufw allow 80
ufw allow 443
ufw allow 22
ufw allow 3306
ufw --force enable

#------------------------------------------------------------------------------------
# Enable SWAP - y
#------------------------------------------------------------------------------------

fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
cp /etc/fstab /etc/fstab.bak
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

#------------------------------------------------------------------------------------
# Install MC - y
#------------------------------------------------------------------------------------

apt -y install mc

#------------------------------------------------------------------------------------
# Gather domain names into array - y
#------------------------------------------------------------------------------------

echo -e "How many domains would you like to set up: \c "
read COUNT

for (( i=1; i<=COUNT; i++ ))
do  
  echo "Please enter domain $i"
   read DOMAIN[i]
done

for (( i=1; i<=COUNT; i++ ))
do  
  echo "Would you like a www version of ${DOMAIN[i]}"
   read -p "(y/n)?" CONT
   if [ "$CONT" = "y" ]; then
   WWW_DOMAIN[i]=www.${DOMAIN[i]}
   fi 
done

#------------------------------------------------------------------------------------
# create user for uploads and disable password login for root 
#------------------------------------------------------------------------------------

sed -i 's/PermitRootLogin yes/PermitRootLogin without-password/g'  /etc/ssh/sshd_config
echo "Please enter username for ssh" 
read username
useradd -m $username -G www-data 
ssh-keygen -t rsa -N '' -f $username 
mkdir -p /home/$username/.ssh
cp $username /home/$username/.ssh/$username
cp $username.pub /home/$username/.ssh/$username.pub
cat /home/$username/.ssh/$username.pub >> /home/$username/.ssh/authorized_keys

#------------------------------------------------------------------------------------
# Get public IP of server
#------------------------------------------------------------------------------------

PUBLIC_IP=`wget http://ipecho.net/plain -O - -q ; echo`
echo $PUBLIC_IP

#------------------------------------------------------------------------------------
# Install Apache, PHP and imagemagick, set Apache to listen on port 8080 - y
#------------------------------------------------------------------------------------

apt-get -y install apache2 php7.3-fpm php7.3 php7.3-common php7.3-mysql php7.3-xml php7.3-xmlrpc php7.3-curl php7.3-gd php7.3-imagick php7.3-cli php7.3-dev php7.3-imap php7.3-mbstring php7.3-opcache php7.3-soap php7.3-zip php7.3-intl imagemagick
wget https://mirrors.edge.kernel.org/ubuntu/pool/multiverse/liba/libapache-mod-fastcgi/libapache2-mod-fastcgi_2.4.7~0910052141-1.2_amd64.deb
dpkg -i libapache2-mod-fastcgi_2.4.7~0910052141-1.2_amd64.deb
sed -i '/Listen/{s/\([0-9]\+\)/8080/; :a;n; ba}' /etc/apache2/ports.conf
sed -i '/*:/{s/\([0-9]\+\)/8080/; :a;n; ba}' /etc/apache2/sites-available/000-default.conf
sed -i 's/memory_limit = 128M/memory_limit = 1024M/g'  /etc/php/7.3/fpm/php.ini
systemctl reload apache2

#------------------------------------------------------------------------------------
# Configure Apache to use mod_fastcgi and rewrite module - y
#------------------------------------------------------------------------------------

a2enmod rewrite
a2enmod actions
sed -i '5 i AddType application\/x-httpd-fastphp .php' /etc/apache2/mods-available/fastcgi.conf 
sed -i '6 i Action application\/x-httpd-fastphp \/php-fcgi' /etc/apache2/mods-available/fastcgi.conf 
sed -i '7 i Alias \/php-fcgi \/usr\/lib/cgi-bin\/php-fcgi' /etc/apache2/mods-available/fastcgi.conf 
sed -i '8 i FastCgiExternalServer \/usr\/lib\/cgi-bin\/php-fcgi -socket \/run\/php\/php7.3-fpm.sock -pass-header Authorization' /etc/apache2/mods-available/fastcgi.conf 
sed -i '9 i  <Directory \/usr\/lib\/cgi-bin>' /etc/apache2/mods-available/fastcgi.conf 
sed -i '10 i Require all granted' /etc/apache2/mods-available/fastcgi.conf 
sed -i '11 i  <\/Directory>' /etc/apache2/mods-available/fastcgi.conf 
systemctl reload apache2
service apache2 restart


#------------------------------------------------------------------------------------
# Create virtual hosts for apache ($a append after last line, i1 before line 1) 
#------------------------------------------------------------------------------------

for (( i=1; i<=COUNT; i++ ))
do  
mkdir /var/www/${DOMAIN[i]}
mkdir /var/www/${DOMAIN[i]}/.well-known
touch /var/www/${DOMAIN[i]}/.htaccess
echo -e "<VirtualHost *:8080>\nServerName ${DOMAIN[i]}\nServerAlias www.${DOMAIN[i]}\nDocumentRoot /var/www/${DOMAIN[i]}\n<Directory /var/www/${DOMAIN[i]}>\nAllowOverride None\nInclude /var/www/${DOMAIN[i]}/.htaccess\n</Directory>\n</VirtualHost>" > /etc/apache2/sites-available/${DOMAIN[i]}.conf
a2ensite ${DOMAIN[i]}
done
chown -R www-data /var/www
chgrp -R www-data /var/www
chmod -R 755 /var/www
systemctl reload apache2

#------------------------------------------------------------------------------------
# Installing and Configuring Nginx for Apache virtual hosts
#------------------------------------------------------------------------------------

apt-get -y install nginx
rm /etc/nginx/sites-enabled/default
touch /etc/nginx/sites-available/apache

echo -e "server {\n  listen 80;\n    server_name ${DOMAIN[@]} ${WWW_DOMAIN[@]};\nlocation / {\nproxy_pass http://127.0.0.1:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" > /etc/nginx/sites-available/apache

ln -s /etc/nginx/sites-available/apache /etc/nginx/sites-enabled/apache
service nginx reload

#------------------------------------------------------------------------------------
# Installing and Configuring mod_rpaf - depreciated
#------------------------------------------------------------------------------------

#apt-get -y install unzip build-essential apache2-dev
#wget https://github.com/gnif/mod_rpaf/archive/stable.zip
#unzip stable.zip
#cd mod_rpaf-stable
#make
#make install
#echo -e "LoadModule rpaf_module /usr/lib/apache2/modules/mod_rpaf.so" > /etc/apache2/mods-available/rpaf.load

#echo -e "<IfModule mod_rpaf.c>\nRPAF_Enable             On\nRPAF_Header             X-Real-Ip\nRPAF_ProxyIPs           $PUBLIC_IP\nRPAF_SetHostName        On\nRPAF_SetHTTPS           On\nRPAF_SetPort            On\n</IfModule>" > /etc/apache2/mods-available/rpaf.conf
#a2enmod rpaf
#systemctl reload apache2
#cd ..

#------------------------------------------------------------------------------------
# Installing and Configuring mod_remoteip 
#------------------------------------------------------------------------------------

a2enmod remoteip
sed -i 's/LogFormat "%h/LogFormat "%a/g' /etc/apache2/apache2.conf 
echo "# disable ETags" >> /etc/apache2/apache2.conf
echo "FileETag None" >> /etc/apache2/apache2.conf
echo "# Trigger additional browser side XSS protection" >> /etc/apache2/apache2.conf
echo 'Header always set X-Xss-Protection "1; mode=block"' >> /etc/apache2/apache2.conf
echo "RemoteIPHeader X-Forwarded-For" >> /etc/apache2/apache2.conf
echo "RemoteIPTrustedProxy 127.0.0.1" >> /etc/apache2/apache2.conf


#------------------------------------------------------------------------------------
# Installing and Configuring wkhtmltopdf
#------------------------------------------------------------------------------------

apt-get -y install libxrender1 xfonts-utils xfonts-base xfonts-75dpi libfontenc1 x11-common xfonts-encodings fontconfig
wget https://downloads.wkhtmltopdf.org/0.12/0.12.5/wkhtmltox_0.12.5-1.bionic_amd64.deb
dpkg -i wkhtmltox_0.12.5-1.bionic_amd64.deb

#------------------------------------------------------------------------------------
# Secure Nginx with Let's Encrypt
#------------------------------------------------------------------------------------

apt-get -y install letsencrypt
echo -e "ssl_protocols TLSv1.2 TLSv1.3;\nssl_prefer_server_ciphers on;\nssl_dhparam /etc/ssl/certs/dhparam.pem; # openssl dhparam -out /etc/nginx/dhparam.pem 4096\nssl_ciphers EECDH+AESGCM:EDH+AESGCM;\nssl_ecdh_curve secp384r1; # Requires nginx >= 1.1.0\nssl_session_timeout  10m;\nssl_session_cache shared:SSL:10m;\nssl_session_tickets off; # Requires nginx >= 1.5.9\nssl_stapling on; # Requires nginx >= 1.3.7\nssl_stapling_verify on; # Requires nginx => 1.3.7\nresolver 8.8.8.8 8.8.4.4 valid=300s;\nresolver_timeout 5s;\nadd_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";\nadd_header X-Frame-Options DENY;\nadd_header X-Content-Type-Options nosniff;\nadd_header X-XSS-Protection "1; mode=block";\n" > /etc/nginx/snippets/ssl-params.conf


for (( i=1; i<=COUNT; i++ ))
do
echo -e "ssl_certificate /etc/letsencrypt/live/${DOMAIN[i]}/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/${DOMAIN[i]}/privkey.pem;" > /etc/nginx/snippets/ssl-${DOMAIN[i]}.conf
letsencrypt certonly -a webroot --webroot-path=/var/www/${DOMAIN[i]} -d ${DOMAIN[i]} 
if [[ ${WWW_DOMAIN[i]} ]]; then
echo -e "ssl_certificate /etc/letsencrypt/live/${WWW_DOMAIN[i]}/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/${WWW_DOMAIN[i]}/privkey.pem;" > /etc/nginx/snippets/ssl-${WWW_DOMAIN[i]}.conf
letsencrypt certonly -a webroot --webroot-path=/var/www/${DOMAIN[i]} -d ${WWW_DOMAIN[i]}
fi
done


openssl dhparam -out /etc/ssl/certs/dhparam.pem 4096

rm /etc/nginx/sites-available/apache
touch /etc/nginx/sites-available/apache
for (( i=1; i<=COUNT; i++ ))
do 
echo -e "server {\n  listen 443 ssl http2;\n include snippets/ssl-${DOMAIN[i]}.conf;\n include snippets/ssl-params.conf;\n server_name ${DOMAIN[i]};\nlocation / {\nproxy_pass http://$PUBLIC_IP:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache	
echo -e "server {\n  listen 80;\n  listen [::]:80;\n  server_name ${DOMAIN[i]};\n  return 301 https://${DOMAIN[i]}$request_uri;\n }" >> /etc/nginx/sites-available/apache	
if [[ ${WWW_DOMAIN[i]} ]]; then
echo -e "server {\n  listen 443 ssl http2;\n include snippets/ssl-${WWW_DOMAIN[i]}.conf;\n include snippets/ssl-params.conf;\n server_name ${WWW_DOMAIN[i]};\nlocation / {\nproxy_pass http://$PUBLIC_IP:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache
echo -e "server {\n  listen 80;\n  listen [::]:80;\n  server_name ${WWW_DOMAIN[i]};\n  return 301 https://${WWW_DOMAIN[i]}$request_uri;\n }" >> /etc/nginx/sites-available/apache	
fi
done
service nginx reload

#------------------------------------------------------------------------------------
# Set Let's Encrypt to Check Certificate Renewal on a Daily Basis Using Cron Job
#------------------------------------------------------------------------------------

touch /etc/cron.daily/letsencrypt
chmod 755 /etc/cron.daily/letsencrypt
echo -e '#!/bin/sh \n \nletsencrypt renew' >> /etc/cron.daily/letsencrypt

#------------------------------------------------------------------------------------
# Reload Nginx Monthly Using Cron Job so that new SSL certificates load
#------------------------------------------------------------------------------------

touch /etc/cron.monthly/reload-nginx
chmod 755 /etc/cron.monthly/reload-nginx
echo -e '#!/bin/sh \n \nservice nginx reload\nservice nginx restart' >> /etc/cron.monthly/reload-nginx

#------------------------------------------------------------------------------------
# Harden Apache Configuration
#------------------------------------------------------------------------------------

a2enmod headers
echo -e "\n# disable ETags\nFileETag None\n\n# Trigger additional browser side XSS protection\nHeader always set X-Xss-Protection \"1; mode=block\"" >> /etc/apache2/apache2.conf
sed -i 's/ServerTokens OS/ServerTokens Prod/g'  /etc/apache2/conf-available/security.conf
sed -i 's/ServerSignature On/ServerSignature Off/g'  /etc/apache2/conf-available/security.conf
#sed -i 's/#Header set X-Content-Type-Options:/Header set X-Content-Type-Options:/g'  /etc/apache2/conf-available/security.conf
#sed -i 's/#Header set X-Frame-Options:/Header set X-Frame-Options:/g'  /etc/apache2/conf-available/security.conf

apt-get -y install libapache2-mod-security2
mv /etc/modsecurity/modsecurity.conf{-recommended,}
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g'  /etc/modsecurity/modsecurity.conf
echo -e '#ServerName for mod security\nServerName localhost' >> /etc/apache2/apache2.conf

service apache2 reload

#------------------------------------------------------------------------------------
# Harden / tweak Nginx Configuration
#------------------------------------------------------------------------------------

sed -i 's/#server_tokens off;/server_tokens off;/g'  /etc/nginx/nginx.conf
sed -i 's/ TLSv1 TLSv1.1 TLSv1.2 / TLSv1.2 TLSv1.3 /g' /etc/nginx/nginx.conf
sed -i 's/768/10000/g' /etc/nginx/nginx.conf
sed -i 's/# multi_accept on;/multi_accept on;/g' /etc/nginx/nginx.conf
sed -i '9 i use epoll;' /etc/nginx/nginx.conf
sed -i '11 i worker_rlimit_nofile    20000;' /etc/nginx/nginx.conf
#sed -i '18 i add_header X-Frame-Options "SAMEORIGIN";' /etc/nginx/nginx.conf
#sed -i '19 i add_header X-XSS-Protection "1; mode=block";' /etc/nginx/nginx.conf


apt-get -y install fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime  = 600/bantime  = 3600/g'  /etc/fail2ban/jail.local
sed -i 's/\[nginx-http-auth\]/\[nginx-http-auth\]\n\nenabled  = true/g'  /etc/fail2ban/jail.local
sed -i 's/\[nginx-botsearch\]/\[nginx-botsearch\]\n\nenabled  = true/g'  /etc/fail2ban/jail.local
service fail2ban restart

#------------------------------------------------------------------------------------
# Install and harden MySQL https://www.digitalocean.com/community/tutorials/how-to-install-mysql-on-ubuntu-18-04 and maybe https://www.digitalocean.com/community/tutorials/how-to-install-and-secure-phpmyadmin-on-ubuntu-18-04
#------------------------------------------------------------------------------------

  echo "Would you like MYSQL installing?"
   read -p "(y/n)?" CONT
   if [ "$CONT" = "y" ]; then
apt install mysql-server
mysql_secure_installation
   fi 
