#!/bin/bash

# Add in the repo Ondrejs PPA as PHP7.1 is not available by default in ubuntu 16.04 and stop Apache

# add-apt-repository ppa:ondrej/php - not needed as added previously 
apt-get update
service apache2 stop

# Install PHP7.1 core

apt-get install php7.2 php7.2-common
apt-get install php7.2-fpm php7.2-mysql php7.2-mbstring php7.2-gd php7.2-imagick php7.2-curl php7.2-dom 
# sed -i 's/memory_limit = 128M/memory_limit = 1024M/g'  /etc/php/7.1/fpm/php.ini

# Edit apache2 to load 7.1

sed -i 's/php7.1-fpm.sock /php7.2-fpm.sock /g' /etc/apache2/mods-enabled/fastcgi.conf
service php7.2-fpm reload
a2enmod proxy_fcgi setenvif
a2enconf php7.2-fpm
service apache2 reload
a2dismod php7.1
service apache2 reload
cp /etc/php/7.1/fpm/php.ini /etc/php/7.2/fpm
cp /etc/php/7.1/fpm/pool.d/www.conf /etc/php/7.2/fpm/pool.d/
sed -i 's/php7.1-fpm.sock/php7.2-fpm.sock/g' /etc/php/7.2/fpm/pool.d/www.conf
service php7.2-fpm reload
service apache2 reload
sudo apt-get remove --auto-remove php7.0
sudo apt-get remove --auto-remove php7.0-common
sudo apt-get remove --auto-remove php7.1
sudo apt-get remove --auto-remove php7.1-common
