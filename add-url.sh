#!/bin/bash

#------------------------------------------------------------------------------------
# Update repos and server
#------------------------------------------------------------------------------------

/usr/bin/apt-get -y update
/usr/bin/apt-get -y upgrade

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
# Create virtual hosts for apache ($a append after last line, i1 before line 1) 
#------------------------------------------------------------------------------------

for (( i=1; i<=COUNT; i++ ))
do  
mkdir /var/www/${DOMAIN[i]}
mkdir /var/www/${DOMAIN[i]}/.well-known
echo -e "<VirtualHost *:8080>\nServerName ${DOMAIN[i]}\nServerAlias www.${DOMAIN[i]}\nDocumentRoot /var/www/${DOMAIN[i]}\n<Directory /var/www/${DOMAIN[i]}>\nAllowOverride All\n</Directory>\n</VirtualHost>" > /etc/apache2/sites-available/${DOMAIN[i]}.conf
a2ensite ${DOMAIN[i]}
chown -R www-data /var/www/${DOMAIN[i]}
chgrp -R www-data /var/www/${DOMAIN[i]}
done
systemctl reload apache2

#------------------------------------------------------------------------------------
# Installing and Configuring Nginx for Apache virtual hosts
#------------------------------------------------------------------------------------

echo -e "server {\n  listen 80;\n    server_name ${DOMAIN[@]} ${WWW_DOMAIN[@]};\nlocation / {\nproxy_pass http://127.0.0.1:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache

ln -s /etc/nginx/sites-available/apache /etc/nginx/sites-enabled/apache
service nginx reload

#------------------------------------------------------------------------------------
# Secure Nginx with Let's Encrypt
#------------------------------------------------------------------------------------

for (( i=1; i<=COUNT; i++ ))
do
echo -e "ssl_certificate /etc/letsencrypt/live/${DOMAIN[i]}/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/${DOMAIN[i]}/privkey.pem;" > /etc/nginx/snippets/ssl-${DOMAIN[i]}.conf
letsencrypt certonly -a webroot --webroot-path=/var/www/${DOMAIN[i]} -d ${DOMAIN[i]} 
if [[ ${WWW_DOMAIN[i]} ]]; then
echo -e "ssl_certificate /etc/letsencrypt/live/${WWW_DOMAIN[i]}/fullchain.pem;\nssl_certificate_key /etc/letsencrypt/live/${WWW_DOMAIN[i]}/privkey.pem;" > /etc/nginx/snippets/ssl-${WWW_DOMAIN[i]}.conf
letsencrypt certonly -a webroot --webroot-path=/var/www/${DOMAIN[i]} -d ${WWW_DOMAIN[i]}
fi
done

for (( i=1; i<=COUNT; i++ ))
do 
echo -e "server {\n  listen 80;\n  listen 443 ssl http2;\n include snippets/ssl-${DOMAIN[i]}.conf;\n include snippets/ssl-params.conf;\n server_name ${DOMAIN[i]};\nlocation / {\nproxy_pass http://$PUBLIC_IP:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache
if [[ ${WWW_DOMAIN[i]} ]]; then
echo -e "server {\n  listen 80;\n  listen 443 ssl http2;\n include snippets/ssl-${WWW_DOMAIN[i]}.conf;\n include snippets/ssl-params.conf;\n server_name ${WWW_DOMAIN[i]};\nlocation / {\nproxy_pass http://$PUBLIC_IP:8080;\n proxy_set_header Host \$host;\n proxy_set_header X-Real-IP \$remote_addr;\n proxy_set_header X-Forwarded-For \$proxy_add_x_forwarded_for;\n proxy_set_header X-Forwarded-Proto \$scheme;} }" >> /etc/nginx/sites-available/apache
fi
done
service nginx reload

