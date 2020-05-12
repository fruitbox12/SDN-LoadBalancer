# CPSC_558

LoadBalancer code for SDN Controller

This file needs to be replaced inside misc folder under pox folder in local pox code and run the below command.

pox/pox.py log.level --DEBUG --ip <SERVER IP> --servers <List of IP's> --method 'algorithm' --weights 'comma seperate values'

Example:

pox/pox.py log.level --DEBUG --ip 10.0.1.1 --servers 10.0.0.1,10.0.0.2,10.0.0.3 --method 'weighted_round_robin' --weights '3,2,1'
