DISCOVERY_PERIOD = 5# #5For discovering topology. do discovery every 5 sec

MONITOR_PERIOD = 10# #5 For monitoring traffic. do monitoring every 5 sec

MONITOR_AND_DELAYDETECTOR_BOOTSTRAP_DELAY= 60 # wait to all the topology being discovered

DELAY_DETECTING_PERIOD = 10 #5For delay detecting. do delay detecting every 5 sec

TOSHOW = False	   # For showing information in terminal

TOSHOW_TM =True # For showing instantaneus Traffic Matrix in terminal

# PATH_TO_FILES = "/home/csnetuofr/monitoring/TM.txt"

#FOR DRSIR
PATH_TO_FILES = "/home/csnetuofr/monitoring/TMPrediction"

NUMBER_OF_NODES = 14

NUMBER_OF_LINKS = 128

'''
for 64 nodes try to run with discover 10, monitor 15, delay 13 but it seems that the monitor is not enough for the drl, 
if you touch it increases rmuco then paila, then savoy to do with 48 nodes
'''