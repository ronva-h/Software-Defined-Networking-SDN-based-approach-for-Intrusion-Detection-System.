# Intrusion-Detection-System-on-Software-defined-networking
Implementation of Intrusion Detection System on Zodiac-FX Software defined networking switch,it checks for the packet count within the time span and if it exceeds the threshold it is detected as intrusion. 
The project is basically built using Ryu controller.

How it works:

The controller will collect the flow stats from the switch for every 5 seconds,and the stats are sent to IDS system ,this is done by building the packet and giving the payload of packet as the flow stats.
The IDS system takes the packet and it compares the flow stats with the threshold.If the flow stat is more than threshold, it is detected as the Intrusion.
