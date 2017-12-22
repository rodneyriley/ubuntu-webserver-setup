#!/bin/bash

#------------------------------------------------------------------------------------
# Update repos and server
#------------------------------------------------------------------------------------

/usr/bin/apt-get -y update
/usr/bin/apt-get -y upgrade

#------------------------------------------------------------------------------------
# Config firewall
#------------------------------------------------------------------------------------

ufw default deny incoming
ufw default allow outgoing
ufw allow 80
ufw allow 443
ufw allow 22
ufw allow 3306
ufw --force enable

#------------------------------------------------------------------------------------
# Enable SWAP 
#------------------------------------------------------------------------------------

fallocate -l 1G /swapfile
chmod 600 /swapfile
mkswap /swapfile
swapon /swapfile
cp /etc/fstab /etc/fstab.bak
echo '/swapfile none swap sw 0 0' | sudo tee -a /etc/fstab

#------------------------------------------------------------------------------------
# Install MC
#------------------------------------------------------------------------------------

/usr/bin/apt-get -y install mc

#------------------------------------------------------------------------------------
# Gather domain names into array
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
# Install Apache and PHP, set Apache to listen on port 8080
#------------------------------------------------------------------------------------

apt-get -y install apache2 libapache2-mod-fastcgi php-fpm php-mysql php-mcrypt php-mbstring php-gd php-curl php-xml php7.0-xml
apt-get -y install 
sed -i '/Listen/{s/\([0-9]\+\)/8080/; :a;n; ba}' /etc/apache2/ports.conf
sed -i '/*:/{s/\([0-9]\+\)/8080/; :a;n; ba}' /etc/apache2/sites-available/000-default.conf
sed -i 's/memory_limit = 128M/memory_limit = 1024M/g'  /etc/php/7.0/fpm/php.ini
systemctl reload apache2

#------------------------------------------------------------------------------------
# Configure Apache to use mod_fastcgi and rewrite module
#------------------------------------------------------------------------------------

#not sure if this should be mods-enabled or mods-available

a2enmod rewrite
a2enmod actions
sed -i '5 i AddType application\/x-httpd-fastphp .php' /etc/apache2/mods-enabled/fastcgi.conf 
sed -i '6 i Action application\/x-httpd-fastphp \/php-fcgi' /etc/apache2/mods-enabled/fastcgi.conf 
sed -i '7 i Alias \/php-fcgi \/usr\/lib/cgi-bin\/php-fcgi' /etc/apache2/mods-enabled/fastcgi.conf 
sed -i '8 i FastCgiExternalServer \/usr\/lib\/cgi-bin\/php-fcgi -socket \/run\/php\/php7.0-fpm.sock -pass-header Authorization' /etc/apache2/mods-enabled/fastcgi.conf 
sed -i '9 i  <Directory \/usr\/lib\/cgi-bin>' /etc/apache2/mods-enabled/fastcgi.conf 
sed -i '10 i Require all granted' /etc/apache2/mods-enabled/fastcgi.conf 
sed -i '11 i  <\/Directory>' /etc/apache2/mods-enabled/fastcgi.conf 
systemctl reload apache2
service apache2 restart


#------------------------------------------------------------------------------------
# Create virtual hosts for apache ($a append after last line, i1 before line 1) 
#------------------------------------------------------------------------------------

for (( i=1; i<=COUNT; i++ ))
do  
mkdir /var/www/${DOMAIN[i]}
mkdir /var/www/${DOMAIN[i]}/.well-known
echo -e "<VirtualHost *:8080>\nServerName ${DOMAIN[i]}\nServerAlias www.${DOMAIN[i]}\nDocumentRoot /var/www/${DOMAIN[i]}\n<Directory /var/www/${DOMAIN[i]}>\nAllowOverride None\nInclude /var/www/${DOMAIN[i]}/.htaccess\n</Directory>\n</VirtualHost>" > /etc/apache2/sites-available/${DOMAIN[i]}.conf
a2ensite ${DOMAIN[i]}
done
chown -R www-data /var/www
chgrp -R www-data /var/www
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
# Installing and Configuring mod_rpaf
#------------------------------------------------------------------------------------

apt-get -y install unzip build-essential apache2-dev
wget https://github.com/gnif/mod_rpaf/archive/stable.zip
unzip stable.zip
cd mod_rpaf-stable
make
make install
echo -e "LoadModule rpaf_module /usr/lib/apache2/modules/mod_rpaf.so" > /etc/apache2/mods-available/rpaf.load

echo -e "<IfModule mod_rpaf.c>\nRPAF_Enable             On\nRPAF_Header             X-Real-Ip\nRPAF_ProxyIPs           $PUBLIC_IP\nRPAF_SetHostName        On\nRPAF_SetHTTPS           On\nRPAF_SetPort            On\n</IfModule>" > /etc/apache2/mods-available/rpaf.conf
a2enmod rpaf
systemctl reload apache2
cd ..

#------------------------------------------------------------------------------------
# Installing and Configuring imagemagick
#------------------------------------------------------------------------------------

apt-get -y install imagemagick
apt-get -y install php-imagick
service apache2 reload
service php7.0-fpm reload

#------------------------------------------------------------------------------------
# Installing and Configuring wkhtmltopdf
#------------------------------------------------------------------------------------

wget http://www.rodneyriley.co.uk/wkhtmltox-0.12.2_linux-trusty-amd64.deb
apt-get -y install libxrender1 xfonts-utils xfonts-base xfonts-75dpi libfontenc1 x11-common xfonts-encodings libxfont1 fontconfig
dpkg -i wkhtmltox-0.12.2_linux-trusty-amd64.deb

#------------------------------------------------------------------------------------
# Secure Nginx with Let's Encrypt
#------------------------------------------------------------------------------------

apt-get -y install letsencrypt
echo -e "ssl_protocols TLSv1.1 TLSv1.2;\nssl_prefer_server_ciphers on;\nssl_ciphers \"EECDH+AESGCM:EDH+AESGCM:AES256+EECDH:AES256+EDH\";\nssl_ecdh_curve secp384r1;\nssl_session_cache shared:SSL:10m;\nssl_session_tickets off;\nssl_stapling on;\nssl_stapling_verify on;\nresolver 8.8.8.8 8.8.4.4 valid=300s;\nresolver_timeout 5s;\nadd_header Strict-Transport-Security \"max-age=63072000; includeSubdomains\";\nadd_header X-Frame-Options DENY;\nadd_header X-Content-Type-Options nosniff;\nssl_dhparam /etc/ssl/certs/dhparam.pem;\n" > /etc/nginx/snippets/ssl-params.conf
for (( i=1; i<=COUNT; i++ ))
do
echo -e "ssl_certificate /etc/letsencrypt/live/${DOMAIN[i]}/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/${DOMAIN[i]}/privkey.pem;" > /etc/nginx/snippets/ssl-${DOMAIN[i]}.conf
letsencrypt certonly -a webroot --webroot-path=/var/www/${DOMAIN[i]} -d ${DOMAIN[i]} 
if [[ ${WWW_DOMAIN[i]} ]]; then
echo -e "ssl_certificate /etc/letsencrypt/live/${WWW_DOMAIN[i]}/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/${WWW_DOMAIN[i]}/privkey.pem;" > /etc/nginx/snippets/ssl-${WWW_DOMAIN[i]}.conf
letsencrypt certonly -a webroot --webroot-path=/var/www/${DOMAIN[i]} -d ${WWW_DOMAIN[i]}
fi
done


openssl dhparam -out /etc/ssl/certs/dhparam.pem 2048

rm /etc/nginx/sites-available/apache
touch /etc/nginx/sites-available/apache
for (( i=1; i<=COUNT; i++ ))
do 
echo -e "server {\n  listen 80;\n  listen 443 ssl http2;\n include snippets/ssl-${DOMAIN[i]}.conf;\n include snippets/ssl-params.conf;\n server_name ${DOMAIN[i]};\nlocation / {\nproxy_pass http://$PUBLIC_IP:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache
if [[ ${WWW_DOMAIN[i]} ]]; then
echo -e "server {\n  listen 80;\n  listen 443 ssl http2;\n include snippets/ssl-${WWW_DOMAIN[i]}.conf;\n include snippets/ssl-params.conf;\n server_name ${WWW_DOMAIN[i]};\nlocation / {\nproxy_pass http://$PUBLIC_IP:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache
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
# Harden Apache Configuration
#------------------------------------------------------------------------------------

a2enmod headers
echo -e "\n# disable ETags\nFileETag None\n\n# Trigger additional browser side XSS protection\nHeader always set X-Xss-Protection \"1; mode=block\"" >> /etc/apache2/apache2.conf

sed -i 's/ServerTokens OS/ServerTokens Prod/g'  /etc/apache2/conf-available/security.conf
sed -i 's/ServerSignature On/ServerSignature Off/g'  /etc/apache2/conf-available/security.conf
sed -i 's/#Header set X-Content-Type-Options:/Header set X-Content-Type-Options:/g'  /etc/apache2/conf-available/security.conf
sed -i 's/#Header set X-Frame-Options:/Header set X-Frame-Options:/g'  /etc/apache2/conf-available/security.conf

apt-get -y install libapache2-modsecurity
mv /etc/modsecurity/modsecurity.conf{-recommended,}
sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/g'  /etc/modsecurity/modsecurity.conf
#sed -i '10 i Include /usr/share/modsecurity-crs/*.conf' /etc/apache2/mods-available/security2.conf 
#sed -i '11 i Include /usr/share/modsecurity-crs/activated_rules/*.conf' /etc/apache2/mods-available/security2.conf 

service apache2 reload

#------------------------------------------------------------------------------------
# Harden Nginx Configuration
#------------------------------------------------------------------------------------

sed -i 's/# server_tokens off;/server_tokens off;/g'  /etc/nginx/nginx.conf
apt-get -y install fail2ban
cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local
sed -i 's/bantime  = 600/bantime  = 3600/g'  /etc/fail2ban/jail.local
sed -i 's/\[nginx-http-auth\]/\[nginx-http-auth\]\n\nenabled  = true/g'  /etc/fail2ban/jail.local
sed -i 's/\[nginx-botsearch\]/\[nginx-botsearch\]\n\nenabled  = true/g'  /etc/fail2ban/jail.local
service fail2ban restart

#fail2ban-client status for testing
#May be some issues with permissions, www area should be apache / www-data users .ssh should be for the user and permissions 600 










