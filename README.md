# ubuntu-webserver-setup
Script that creates a web server running Nginx / Apache / php / imagemagick / htmltopdf / Lets Encrypt. Script automatically configures basic security and any number of virtual hosts including the process of creating SSL certificates. Finally the script sets up a user for SSH and joins them to the www-data group. Intended as a starting point and enhancements / comments very welcome.

Upload the scripts can be done in lots of ways but the following command works well

scp server-setup.sh root@your.server.ip.here:.

Once uploaded set it to be executable by whatever user or group you choose. 755 works well generally (chmod 755 server-setup.sh)

