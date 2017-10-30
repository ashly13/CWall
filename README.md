# CWall
A simple implementation of Linux Firewall in C using Netfilter framework. This project was coded and tested in Ubuntu 17.04.

# How to Run

* Install linux kernel headers using the command
    `sudo apt-get install linux-source`
* Run make file using the command
    `make`
* Load the firewall kernel module using
    `sudo insmod ./CWall.ko`
* Unload the firewall kernel module using
    `sudo rmmod ./CWall.ko`
 
