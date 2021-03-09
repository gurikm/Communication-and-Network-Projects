Name:Gurik Manshahia
Student ID: V00863509
TCP_Analysis.py
Date:2021-03-07

How to run the code using linux terminal:
	PLease install dpkt to run code
	python3 TrafficAnalysis.py <name of cap file>
	python3 TrafficAnalysis.py sample-capture-file.cap

program will return 4 different sections when excuted: python3 TrafficAnalysis.py sample-capture-file.cap
A) Total number of connections

B) Connections' details

Connection N:
Source Address:
Destination address:
Source Port:
Destination Port:
Status:Duration:
(Only if the connection is complete provide the following information)
Start time:
End Time:
Number of packets sent from Source to Destination:
Number of packets sent from Destination to Source:
Total number of packets:
Number of data bytes sent from Source to Destination:
Number of data bytes sent from Destination to Source:
Total number of data bytes:
END

C) General

Total number of complete TCP connections:
Number of reset TCP connections:
Number of TCP connections that were still open when the trace capture ended

D) Complete TCP connections:

Minimum time duration:
Mean time duration:
Maximum time duration:

Minimum RTT value:
Mean RTT value:
Maximum RTT value:

Minimum number of packets including both send/received:
Mean number of packets including both send/received:
Maximum number of packets including both send/received:

Minimum receive window sizeincluding both send/received:
Mean receive window sizeincluding both send/received:
Maximum receive window sizeincluding both send/received:

References:
https://dpkt.readthedocs.io/en/latest/api/api_auto.html
https://pythontic.com/modules/socket/inet_ntoa
https://hynek.me/articles/hashes-and-equality/