# Ryu_Controller
Loughborough University - ECS - Part C Project - SDN Ryu Controller
Loughborough University - CyberSecurity and Big Data - MSc Dissertation - Machine Learning

Branches:
---
    + Master - Undergraduate Part C Project
    + MSc - Postgraduate MSc Project

Folders:
---
    + Performance_Tests - Performance testing of Ryu Controllers
    + Ryu_Controller - Various Ryu Controllers
    + NN_Testing - Neural network testing

Classes:
---
    + l2.py - Dumb layer 2 switch
    + LearningSwitch.py - Learning layer 2 switch
    + MitigationController.py - Ryu controller containing mitigation methods
    + DDoSSetection.py - DDoS detection module
    + PortStatsController.py - Ryu controller using port stats for detection (Final Product)
    
Running Custom Network/Controller:
---
    Network: $ sudo Network/TestTopo.py
    Controller: $ ryu-manager --ofp-tcp-listen-port 7777 Ryu_Controller/LearningSwitch.py

