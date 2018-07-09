# BuildScriptV2
A shell script that contains a procedural list of bash and sed commands to set up and configure a web server (VPS) running Ubuntu 16.04 with fail2ban, firewalld, nginx, and ntp.

Spin-up a VPS on an IaaS, like DigitalOcean, that’s running `fail2ban`, `firewalld`, `nginx`, and `ntp`.

Send a screenshot of the output of `systemctl status fail2ban firewalld nginx ntp`.