import random
import os
import time 
import json

CreateRuleSet = 1
all_rules = {"Ether_rules": [], "IPv4rules": [], "IPv6rules": [], "TCPrules": [], "UDPrules": [], "ICMPrules": []}

def saveRules(count):
    filename = "rules"+str(count)+".txt"
    with open(filename, "w") as outfile:
        json.dump(all_rules, outfile)

# choice between two
binary = [0,1]

# IP traffic attributes
Dest_Ip = "192.168.100.6"
TTL_options =[64,128,196,255]
ToS_Values = [40, 80, 160, 320]

#UDP traffic attributes
Source_port_choices = [80, 53, 403]
Dest_port_choices = [80, 403,  5555]

# ICMP traffic attributes
Type_choices = [0,3,4,5,8]
Code_choices = [0,1,2,3,4,5]

# TCP traffic attributes
syn_choices = [0,1]
urg_choices = [0,1]
rst_choices = [0,1]
Source_port_choices_TCP = [80, 53, 403]
Dest_port_choices_TCP = [80, 403,  5555]

# Ethernet traffic attributes
Protocol_choices = [0,1,2,3,4,5]

count =  1

while True:

    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    
    # IP traffic
    TTL_selected = random.choice(TTL_options)
    Tos_value_selected = random.choice(ToS_Values)
    command = "nping -c 10 --delay 20ms --tcp -p 9876 --ttl " + str(TTL_selected) +  " --tos " +  str(Tos_value_selected) + " " + str(Dest_Ip)
    print(command)
    #os.system(command)

    if(CreateRuleSet == 1):
        rule_id = random.randint(1,1000)
        
        binary_selected = random.choice(binary)
        if(binary_selected == 1):
            Action = "Allow"
        else:
            Action = "Discard"

        rule_struct = {}
        rule_struct["rule_id"] = rule_id
        rule_struct["v4source_addr"] = ""
        rule_struct["v4dest_addr"] = ""
        rule_struct["ipv4protocol"] = int(random.choice(Protocol_choices))
        rule_struct["h_len"] = int(40)
        rule_struct["ttl"] = int(TTL_selected)
        rule_struct["tos"] = int(Tos_value_selected)
        rule_struct["rule"] = Action
        all_rules["IPv4rules"].append(rule_struct)


    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    

    # UDP traffic
    Source_Port_Selected = random.choice(Source_port_choices)
    binary_selected = random.choice(binary)
    if(binary_selected == 1):
        Dest_Port_Selected = random.choice(Dest_port_choices)
    else:
        Dest_Port_Selected = 9876
    command = "nping -c 10 --delay 20ms --udp -p " + str(Dest_Port_Selected) + " -g " + str(Source_Port_Selected) + " " + str(Dest_Ip)
    #os.system(command)
    print(command)

    if(CreateRuleSet == 1):
        rule_id = random.randint(1,1000)
        
        binary_selected = random.choice(binary)
        if(binary_selected == 1):
            Action = "Allow"
        else:
            Action = "Discard"

        rule_struct = {}
        rule_struct["rule_id"] = rule_id
        rule_struct["udpsrc_port"] = int(Source_Port_Selected)
        rule_struct["udpdest_port"] = int(Dest_Port_Selected)
        rule_struct["rule"] = Action
        all_rules["UDPrules"].append(rule_struct)

    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************

    # ICMP traffic
    Type_selected = random.choice(Type_choices)
    Code_selected = random.choice(Code_choices)
    command = "nping -c 10 --delay 20ms --icmp --icmp-type " + str(Type_selected) + " --icmp-code " + str(Code_selected) + " " + str(Dest_Ip)
    #os.system(command)
    print(command)

    if(CreateRuleSet == 1):
        rule_id = random.randint(1,1000)
        
        binary_selected = random.choice(binary)
        if(binary_selected == 1):
            Action = "Allow"
        else:
            Action = "Discard"

        rule_struct = {}
        rule_struct["rule_id"] = rule_id
        rule_struct["icmp4type"] = Type_selected
        rule_struct["icmp4code"] = Code_selected
        rule_struct["rule"] = Action
        all_rules["ICMPrules"].append(rule_struct)


    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************

    # TCP traffic
    Syn_selected = random.choice(syn_choices)
    if(Syn_selected == 1):
        syn = "syn,"
    else:
        syn = ""

    URG_selected = random.choice(urg_choices)
    if(URG_selected == 1):
        urg = "urg,"
    else:
        urg = ""

    rst = "rst"

    Source_Port_Selected_TCP = random.choice(Source_port_choices_TCP)
    Dest_Port_Selected_TCP = random.choice(Dest_port_choices_TCP)
    command = "nping -c 10 --delay 20ms --tcp -g "+ str(Source_Port_Selected_TCP) +" -p " + str(Dest_Port_Selected_TCP) +  " --flags " +  str(syn) + str(urg) +  str(rst) + " " + str(Dest_Ip)
    #os.system(command)
    print(command)

    if(CreateRuleSet == 1):
        rule_id = random.randint(1,1000)
        
        binary_selected = random.choice(binary)
        if(binary_selected == 1):
            Action = "Allow"
        else:
            Action = "Discard"

        rule_struct = {}
        rule_struct["rule_id"] = rule_id
        rule_struct["tcpsrc_port"] = int(Source_Port_Selected_TCP)
        rule_struct["tcpdest_port"] = int(Dest_Port_Selected_TCP)
        rule_struct["flag_urg"] = int(random.choice(binary))
        rule_struct["flag_syn"] = int(random.choice(binary))
        rule_struct["flag_rst"] = int(random.choice(binary))
        rule_struct["rule"] = Action
        all_rules["TCPrules"].append(rule_struct)

    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************
    # ******************************************************************************************************************************************

    # Ethernet traffic
    protocol_selected = random.choice(Protocol_choices)
    binary_selected = random.choice(binary)
    if(binary_selected == 1):
        Dest_mac = "08:00:27:ab:ba:9d"
    else:
        Dest_mac = ""

    binary_selected = random.choice(binary)
    if(binary_selected == 1):
        Source_mac = "08:00:27:72:b6:ab"
    else:
        Source_mac = ""

    command = "nping -c 10 --delay 20ms -arp "+ " --dest-mac " + str(Dest_mac) +" -p " + " --source-mac " + str(Source_mac) +  " --ether-type " +  str(protocol_selected)  + " " + str(Dest_Ip)
    #os.system(command)
    print(command)

    if(CreateRuleSet == 1):
        rule_id = random.randint(1,1000)
        
        binary_selected = random.choice(binary)
        if(binary_selected == 1):
            Action = "Allow"
        else:
            Action = "Discard"

        rule_struct = {}
        rule_struct["rule_id"] = rule_id
        rule_struct["source_mac"] = Source_mac
        rule_struct["dest_mac"] = Dest_mac
        rule_struct["ether_proto"] = int(protocol_selected)
        rule_struct["rule"] = Action
        all_rules["Ether_rules"].append(rule_struct)


    saveRules(count)
    count = count + 1
    time.sleep(2)
    