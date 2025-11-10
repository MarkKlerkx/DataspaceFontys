This folder contains parts of the following repository: https://github.com/wistefan/deployment-demo/tree/main


**Consumer/Provider values.yaml-template**

Before transfering the template to the real values.yaml you have to execute the following commands:

*export INTERNAL_IP=$(ip route get 1.1.1.1 | awk '{print $7}')*

This command will create a variable to get the internal ip-address of the server.
