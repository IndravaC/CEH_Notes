# CEH_Notes

# IMPORTANT LINKS
    
    Prep guide : https://medium.com/@xaferima/navigating-the-ceh-practical-exam-unveiling essential-tools-and-practices-2023-9ccb504430ca 
    https://github.com/dhabaleshwar/CEHPractical/blob/main/Everything%20You%20Need.md 
    https://github.com/cmuppin/CEH/blob/main/CEH-Prac%20Guide 
    https://github.com/Samsar4/Ethical-Hacking-Labs/blob/master/5-System-Hacking/9-Steganography.md 
    https://github.com/nirangadh/ceh-practical 
    Aspen : https://aspen.eccouncil.org/Account/Login?ReturnUrl=%2fCEHv12%2fTraning%3fa%3dlXTXGuJCzho%2bnr%2fXcU1isQ%3d%3d&a=lXTXGuJCzho+nr/XcU1isQ== 
    https://github.com/CyberSecurityUP/Guide-CEH-Practical-Master 
    https://medium.com/techiepedia/certified-ethical-hacker-practical-exam-guide-dce1f4f216c9 
    CEH e-courseware : https://bookshelf.vitalsource.com/reader/books/9798885931144/pageid/5703 
    CEH notes : https://github.com/Aftab700/CEH_Notes 


# IMPORTANT DOCS 



# Footprinting and Recon

  Module 2 : Footprinting and Reconnaissance 

  

Lab 1 : Search engines 

  

Task 1 : Advanced Google Hacking Techniques 

intitle:login site:eccouncil.org 

filetype:pdf ceh 

cache:www.eccouncil.org  // Returns cached version of the website 

allinurl:EC-Council career  // Returns only pages containing the words "EC-Council" and "career" 

inurl: copy site:www.eccouncil.org  // Returns only pages in EC-Council site in which the URL has "copy" 

allintitle: detect malware  // Rerturns only pages conatining "detect" and "malware" in the title 

inanchor:Norton  // Returns pages with anchored text "Norton" 

allinanchor:best cloud service provider  // Returns pages in which the anchor text on links to words 

link:www.eccouncil.org  // Finds pages that points to home page of EC-Council's 

related:www.eccouncil.org  // Search engines provides pages website similar to eccouncil 

info:eccouncil.org  // Provides information about the www.eccouncil.org home page 

location:EC-Council  // Finds info about specific location of EC COuncil and related info 

  

Task 2 : Info from Video Search Engines 

1. Go to youtube and search eccouncil 

2. Select any video and right click copy link 

3. open new tab and in address bar type https://mattw.io/youtube-metadata/  to open youtube metadata 

4. Submit video , playlist or channel in a link bar provided 

5. All details can be observed 

8. Scroll down to find Statistics, Geolocation, Status etc 

9. Under thumbnail click to reverse image search 

10. You can use other video search engines such as Google videos (https://www.google.com/videohp), Yahoo videos (https://in.video.search.yahoo.com), etc.; video analysis tools such as EZGif (https://ezgif.com), VideoReverser.com (https://www.videoreverser.com) etc.; and reverse image search tools such as TinEye Reverse Image Search (https://tineye.com), Yahoo Image Search (https://images.search.yahoo.com), etc. to gather crucial information about the target organization. 

  

Task 3 : Gather info from FTP Search Engines 

1. Open firefox and type https://www.searchftps.net/ to open NAPALM FTP indexer 

2. Type microsoft and search to get results of critical files and other data 

3. You can also use FreewareWeb FTP File Search (https://www.freewareweb.com) to gather crucial FTP information about the target organization. 

  

Task 4 : Gather info using IOT search engines (Shodan, Censys) 

1. Open to https://www.shodan.io/ 

2. Type amazon in search bar to obtain results and details of vulnerable IOT devices related to amazon 

3. You can also use Censys (https://censys.io) 

  

  

Lab 2 : Performing footprinting through web services 

  

Task 1 : Find company's domains and subdomains using netcraft, sublist3r , pentest-tools find subdomains 

1. Open Netcraft https://www.netcraft.com 

2. Visit resources > research tools 

3. Also visit to Sublist3r (https://github.com), Pentest-Tools Find Subdomains (https://pentest-tools.com) 

  

Task 2 : Gathering personal info using PeekYou, etc 

1. PeekYou (  https://www.peekyou.com ) 

2. Spokeo (https://www.spokeo.com) 

3. pipl (https://pipl.com)  

4. Intelius (https://www.intelius.com)  

5. BeenVerified (https://www.beenverified.com) 

  

Task 3 : Gather email list using theHarvester 

1. Open Parrot Security or kali linux 

2. In terminal type theHarvester -d microsoft.com -l 200 -b baidu  // -d for domain , -l for no. of results, -b for data source 

3. Email id can be listed 

  

Task 4 : Gather info using Deep and Dark Web 

1. Download Tor browser and connect to Tor 

2. Search hackerforhire ( as an example. This site cannot be found in google ) 

3. Tor uses duckduckgo search engine 

4. You can also anonymously explore the following onion sites using Tor Brower to gather other relevant information about the target organization: 

  

    The Hidden Wiki is an onion site that works as a Wikipedia service of hidden websites. (http://zqktlwiuavvvqqt4ybvgvi7tyo4hjl5xgfuvpdf6otjiycgwqbym2qad.onion/wiki) 

  

    FakeID is an onion site for creating fake passports (http://ymvhtqya23wqpez63gyc3ke4svju3mqsby2awnhd3bk2e65izt7baqad.onion) 

  

    Cardshop is an onion site that sells cards with good balances (http://s57divisqlcjtsyutxjz2ww77vlbwpxgodtijcsrgsuts4js5hnxkhqd.onion) 

5. ExoneraTor (https://metrics.torproject.org), OnionLand Search engine (https://onionlandsearchengine.com) are some other tools 

  

Task 5 : Determining target OS through Passive Footprinting  

1. Use Censys search(https://search.censys.io/?q=) 

2. Netcraft 

3. Shodan 

  

  

Lab 3 : Footprinting through social networking sites 

  

Task 1 : Gather employee info from linkedin using theHarvester 

1. In parrot terminal : theHarvester -d eccouncil -l 200 -b linkedin 

  

Task 2 : Info using Sherlock 

1. In terminal, in folder where sherlock python file is present : python3 sherlock satya nadella 

2. Also use tools like Social Searcher (https://www.social-searcher.com), UserRecon (https://github.com) 

  

  

Lab 4 : Website Footprinting 

  

Task 1 : Gather info using ping command 

1.  ping www.certifiedhacker.com -f -l 1500  // -f for not packet fragmenting , -l for buffer size 

  

Task 2 : Gather info using Photon 

1. python3 photon.py -h  // -h for help 

2. python3 photon.py -u http://www.certifiedhacker.com 

3. python3 photon.py -u http://www.certifiedhacker.com -l 3 -t 200 --wayback  

4. Navigate to photon directory to view results 

  

Task 3 : Gather info using Central Ops  

1. Go to central ops website https://centralops.net and search 

2. Other tools : Website Informer (https://website.informer.com), Burp Suite (https://portswigger.net), Zaproxy (https://www.zaproxy.org) 

  

Task 4 : Extract company's data using web data extractor 

1. In the Windows 11 machine, navigate to E:\CEH-Tools\CEHv12 Module 02 Footprinting and Reconnaissance\Web Spiders\Web Data Extractor and double-click wdepro.exe. 

2. Install in system 

3. Click new session and type url ( eg https://www.certifiedhacker.com) and start 

4. You can also use other web spiders such as ParseHub (https://www.parsehub.com), SpiderFoot (https://www.spiderfoot.net), etc. to extract the target organization’s data. 

  

Task 5 : Mirror a Target Website using HTTrack Web Site Copier 

1. In windows desktop open winhttrack website copier 

2. You can also use other mirroring tools such as Cyotek WebCopy (https://www.cyotek.com), etc. to mirror a target website. 

  

Task 6 : Gather Information About a Target Website using GRecon 

1. In linux terminal type python3 grecon.py 

  

Task 7 : Gather a wordlist from target website using CEWL 

1. In terminal type cewl -d 2 -m 5 https://www.certifiedhacker.com  // -d for depth , -m min word len 

2. By default, the wordlist file gets saved in the root directory. Type pluma wordlist.txt and press Enter to view the extracted wordlist. 

  

  

Lab 5 : Performing Email Footprinting 

  

Task 1 : Gather info using eMailTrackerPro 

1. Go to windows machine > CEH tools > eMailTrackerPro 

2. Other tools Infoga (https://github.com), Mailtrack (https://mailtrack.io) 

  

  

Lab 6 : Whois Footprinting 

1.  http://whois.domaintools.com 

2. You can also use other Whois lookup tools such as SmartWhois (https://www.tamos.com), Batch IP Converter (http://www.sabsoft.com) 

  

Lab 7 : DNS Footprinting 

Task 1 : Gather DNS info using nslookup 

1. nslookup (command line interface) 

2. Online tool : http://www.kloth.net/services/nslookup.php 

3. You can also use DNS lookup tools such as DNSdumpster (https://dnsdumpster.com), DNS Records (https://network-tools.com) 

  

Task 2 : Reverse DNS Lookup using Reverse IP Domain CHECK and DNSRecon 

1. https://www.yougetsignal.com 

2. Parrot : cd dnsrecon 

3. execute dnsrecon.py 

  

Task 3 : Gather Information of Subdomain and DNS Records using SecurityTrails 

1.  https://securitytrails.com/ 

2. You can also use DNSChecker (https://dnschecker.org), and DNSdumpster (https://dnsdumpster.com), etc. to perform DNS footprinting on a target website. 

  

  

Lab 8 : Perform Network Footprinting 

  

Task 1 : Locate Network Range 

1. https://www.arin.net/about/welcome/region 

  

Task 2 : Perform Network Tracerouting 

1. tracert (in Windows) 

2. traceroute ( in Linux) 

3. You can also use other traceroute tools such as VisualRoute (http://www.visualroute.com), Traceroute NG (https://www.solarwinds.com), etc. to extract additional network information of the target organization. 

  

  

Lab 9 : Perform Footprinting using Various Footprinting Tools 

1. Recon-ng 

2. Maltego 

3. OSRFramework 

4. FOCA 

5. BillCipher 

6. OSINT Framework 

7. You can also use footprinting tools such as Recon-Dog (https://www.github.com), Grecon (https://github.com), Th3Inspector (https://github.com), Raccoon (https://github.com), Orb (https://github.com), etc. to gather additional information related to the target company. 




# Enumeration
#Important Links

Network Services 1 Room THM : https://github.com/AJChestnut/Network-Services-TryHackMe-Writeup 
Network Services 2 Room THM : https://blog.davidvarghese.dev/posts/tryhackme-network-services-2/ 

#SSH ENUMERATION 
Link for metasploitable 2 login using ssh : https://medium.com/@jeelmakwana04/metasploitable-2-solution-using-metasploit-framework-ssh-b109b18943e1 

#NETBIOS ENUMERATION 

NetBIOS is an acronym that stands for Network Basic Input Output System. It enables computer communication over a  LANand the sharing of files and printers. TCP/IPnetwork devices are identified using NetBIOS names (Windows). It must be network-unique and limited to 16 characters, with 15 reserved for the device name and the 16th reserved for identifying the type of service running or name record type. 

 

WINDOWS CMD 2019 

    FIND NETBIOS NAME TABLE - nbtstat -a <ip> ( -a for name table) 

    FIND CACHE - nbtstat -c ( -c for contents ) 

    CONNECTION STATUS - net use (The output displays information about the target such as connection status, shared folder/drive and network information) 

 

NETBIOS ENUMERATOR 

( Can also be used to find out domain controller) 

    IN WINDOWS 11 - open netbios enumerator GUI 

    Under IP range to scan, enter an IP range in the from and to fields and click the Scan button to initiate the scan (In this example, we are targeting the IP range 10.10.1.15-10.10.1.100). 

    Click on the expand icon (+) to the left of the 10.10.1.19 and 10.10.1.22 IP addresses in the left pane of the window. Then click on the expand icon to the left of NetBIOS Names to display NetBIOS details of the target IP address. 

 

NMAP 

    MAC ADDRESSES/ HOST SCRIPT RESULTS/NETBIOS NAME - nmap -sV -v --script nbstat.nse <targ_ip> 

    nmap -sU -sV -v --script nbstat.nse (The scan results appear, displaying the open NetBIOS port (137) and, under the Host script results section, NetBIOS details such as NetBIOS name, NetBIOS user, and NetBIOS MAC of the target system) 



 #SNMP ENUMERATION 

     SNMP ( Simple Network Management Protocol ) is an application layer protocol 

    Uses UDP port number 161 / 162. 

    It is used to monitor and manage network devices like PC, Switch, Router, Server, etc. 

 

Tools used to Enumerate : 

    nmap 

    snmp-walk 

    Softperfect network scanner 

    Metasploit 

 

What to enumerate : 

(PENTESTER GUY) 

    Default UDP ports used by SNMP. 

    Identify the processes running in the target machine using NMAP. 

    List all valid community strings to the server using nmap scripting engine. 

    List all valid community strings to the server using snmp_login metasploit module. 

    List all interfaces of the machine. Use appropriate nmap scripts. 

 

ENUMERATE USING SNMP-CHECK 

LIST ALL INFORMATION, HOSTNAMES, USER, SERVER , NETWORK INFORMATION, NETWORK INTERFACES, NETWORK IP AND ROUTING INFORMATION, AND TCP CONNECTIONS AND LISTENING PORTS, PROCESS, STORAGE, ETC. 

    1. 1. FIRST SCAN THE TARGET : nmap -sU -p 161 <ip> 

    parrot os - snmp-check <targ_ip>  

 

ENUMERATION USING SOFTPERFECT NETWORK SCANNER 

    GO TO WINDOWS : Open softperfect network scanner GUI > Go to remote snmp from options > mark all / none > select ip click properties > Take info 

    Click on (+) option > Open device > select suitable. 

 

ENUMERATION USING SNMPWALK 

    IN PARROT OS : snmpwalk -v1 -c public <targ_ip> ( -v for SNMP version number (1 or 2c or 3) and –c: sets a community string) 

    snmpwalk -v2c -c public [Target IP Address] and press Enter to perform SNMPv2 enumeration on the target machine. 

 

NMAP  

    nmap -sU -p 161 --script=snmp-sysdescr <TARG_IP> ( The result appears displaying information regarding SNMP server type and operating system details) 

    nmap -sU -p 161 --script=snmp-processes <targ_ip> 

    nmap -sU -p 161 --script=snmp-win32-software <targ_ip> 

    nmap -sU -p 161 --script=snmp-interfaces <targ_ip>  

 

PENTESTER GUY VIDEOS 

    snmp-check <t_ip> 

    nmap -sU -p 161 --script=snmp-processes <targ_ip> 

    List community strings : nmap -sU -p 161 --script=snmp-brute <targ_ip> 

    USE METASPLOIT : msfconsole 

    search snmp 

    use snmp_login 

    use auxiliary/scanner/snmp/snmp_login 

    show options 

    set RHOSTS <t_ip> 

    See all other options such as port ( 161 / 162 ) 

    exploit 

    WE WILL GET PRIVATE AND PUBLIC STRINGS 

    FIND INTERFACES : nmap -sU -p 161 --script=snmp-interfaces <targ_ip> 



 #LDAP ENUMERATION 

 LDAP (Lightweight Directory Access Protocol) is an Internet protocol for accessing distributed directory services over a network. LDAP uses DNS (Domain Name System) for quick lookups and fast resolution of queries. A client starts an LDAP session by connecting to a DSA (Directory System Agent), typically on TCP port 389, and sends an operation request to the DSA, which then responds. BER (Basic Encoding Rules) is used to transmit information between the client and the server. One can anonymously query the LDAP service for sensitive information such as usernames, addresses, departmental details, and server names. 

 

ENUMERATION USING ACTIVE DIRECTORY EXPLORER (AD EXPLORER)  

    GO TO WINDOWS > FIND AD EXLORER ( Z:\CEHv12 Module 04 Enumeration\LDAP Enumeration Tools\Active Directory Explorer and double-click ADExplorer.exe) 

    CONNECT TO : TARGET IP > CLICK OK 

    EXPAND : Now, expand DC=CEH, DC=com, and CN=Users by clicking “+” to explore domain user details. 

    FIND USERNAME : Click any username 

    RIGHT CLICK > MODIFY 

 

PYTHON AND NMAP  

    nmap -sU -p 389 <T_IP> 

    nmap -p 389 --script ldap-brute --script-args ldap.base='"cn=users,dc=CEH,dc=com"' <t_ip> 

    OPEN PYTHON3 : python3 

    TYPE CODE :  

import ldap3 

server=ldap3.Server(’[Target IP Address]’, get_info=ldap3.ALL,port=[Target Port]) ## TARGET PORT IS 389 

connection=ldap3.Connection(server)  

connection.bind() and press Enter to bind the connection.  

server.info and press Enter to gather information such as naming context or domain name 

connection.search(search_base='DC=CEH,DC=com',search_filter='(&(objectclass=*))',s earch_scope='SUBTREE', attributes='*') 

connection.entries  

and press Enter to retrieve all the directory objects. 

 

In the python3 shell, type connection.search(search_base='DC=CEH,DC=com',search_filter='(&(objectclass=perso n))',search_scope='SUBTREE', attributes='userpassword')  

and press Enter. True response indicates that the query is successfully executed. 

Type connection.entries and press Enter to dump the entire LDAP information. 

 

ENUMERATION USING LDAPSEARCH  

    PARROT OS : ldapsearch -h [T_ip] -x -s base namingcontexts (-x: specifies simple authentication, -h: specifies the host, and -s: specifies the scope.) 

    ldapsearch -h [Target IP Address] -x -b “DC=CEH,DC=com” 

    ldapsearch -x -h [Target IP Address] -b "DC=CEH,DC=com" "objectclass=*"  

 

ENUM4LINUX 

    Parrot : enum4linux <t_ip> (Number of users , servers , and a lot more) 



#NFS ENUMERATION 

NFS enumeration is a method by which exported directories and shared data on target systems is extracted.  

The Network File System (NFS) is a distributed file system protocol that allows a client to access files over a network as if those files were on the client’s local file system. NFS is often used in enterprise environments for file sharing and data access. NFS uses the Transmission Control Protocol (TCP) to provide reliable delivery of data over the network and typically runs on TCP port 2049, which is the default port for NFS over TCP. 

 

NFS ENUMERATION USING RPCSCAN AND SUPERENUM 

    GO TO WINDOWS 19 : Open SERVER MANAGER from START option. 

    Click Add roles and features. 

    The Add Roles and Features Wizard window appears. Click Next here and in the Installation Type and Server Selection wizards. 

    The Server Roles section appears. Expand File and Storage Services and select the checkbox for Server for NFS under the File and iSCSI Services option, as shown in the screenshot. Click Next. 

    Note: In the Add features that are required for Server for NFS? pop-up window, click the Add Features button. 

    In the Features section, click Next. The Confirmation section appears; click Install to install the selected features. 

    The features begin installing, with progress shown by the Feature installation status bar. When installation completes, click Close. 

    PARROT OS : nmap -p 2049 <t_ip> 

    cd SuperEnum  

    echo "<targ_ip" >> Target.txt  

    ./superenum and press Enter. Under Enter IP List filename with path, type Target.txt, and press Enter. 

    The script starts scanning the target IP address for open NFS and other. Note: The scan will take approximately 15-20 mins to complete. 

    After the scan is finished, scroll down to review the results. Observe that the port 2049 is open and the NFS service is running on it. 

    In the terminal window, type cd .. and press Enter to return to the root directory. 

    RPCSCAN : cd RPCScan 

    python3 rpc-scan.py [Target IP address] --rpc 



#DNS ENUMERATION 

    Domain Name Server 

    Domain Name System(DNS) is nothing but a program that converts or translates a website name into an IP address and vice versa. 

    Port - 53 

 

ZONE TRANSFER 

    FIND NAME SERVER - dig ns <www>/<ip> (ns for name server) 

    ZONE TRANSFER - dig @ns1.bluehost.com(name server) www(target domain) axfr ( axfr is zone transfer ) 

    PERFORM DNS ENUMERATION IN WINDOWS DNS SERVER - nslookup 

    set querytype=soa 

    certifiedhacker.com (target domain without www) 

    ls -d ns1.bluehost.com ( ls -d request zone transfer to a specified name server) 

 

DNSSEC Zone Walking 

    IN PARROT TERMINAL GO TO DNSRECON DIRECTORY - cd dnsrecon 

    chmod +x ./dnsrecon.py 

    ./dnsrecon.py -h 

    ./dnsrecon.py -d <site/ip> -z ( -d for domain site and -z for dnssec zone transfer) 

 

NMAP  

    nmap --script=broadcast-dns-service-discovery <SITE/IP> 

    BRUTE FORCE ALL DOMAINS/HOSTNAMES - nmap -T4 -p 53 --script dns-brute <ip> 

    FIND HOSTS OR SRV RECORDS - nmap --script dns-srv-enum --script-args "dns-srv-enum.domain='certifiedhacker.com'” 

 

DNS ENUMERATION 

( BRUTE FORCING ) ( YOUTUBE PART ) 

    ENUMERATE ALL - dnsenum zonetransfer.me 

    ANOTHER TOOL - fierce -dns zonetransfer.me 

    BRUTE-FORCE - dnsmap zonetransfer.me -w /usr/share/wordlist/SecList/Discovery/DNS/dns-jhaddix.txt 

    fierce -dns zonetransfer.me -wordlist /usr/share/wordlist/SecList/Discovery/DNS/fiercehostlist.txt 



#SMTP ENUMERATION 

SMTP enumeration determines a valid list of user accounts on the SMTP server. 

 

SMTP ENUMERATION USING NMAP 

    nmap -p 25 --script=smtp-enum-users <t_ip> 

    nmap -p 25 --script=smtp-open-relay <t_ip> 

    nmap -p 25 --script=smtp-commands <t_ip> 

 

 

 

SMTP ENUMERATION AND EXPLOITATION (TRYHACKME) 

 

Reference: 

https://computer.howstuffworks.com/e-mail-messaging/email3.htm 

https://tryhackme.com/r/room/networkservices2 

 

What is SMTP? 

SMTP stands for "Simple Mail Transfer Protocol". It is utilised to handle the sending of emails. In order to support email services, a protocol pair is required, comprising of SMTP and POP/IMAP. Together they allow the user to send outgoing mail and retrieve incoming mail, respectively.  

The SMTP server performs three basic functions: 

     It verifies who is sending emails through the SMTP server. 

     It sends the outgoing mail 

     If the outgoing mail can't be delivered it sends the message back to the sender 

Most people will have encountered SMTP when configuring a new email address on some third-party email clients, such as Thunderbird; as when you configure a new email client, you will need to configure the SMTP server configuration in order to send outgoing emails.  

 

 

POP and IMAP 

POP (Post Office Protocol) and IMAP (Internet Message Access Protocol) are email protocols used to transfer emails between a client and a mail server. The key difference is that POP downloads emails from the server to the client, while IMAP syncs the inbox across devices, ensuring changes made on one device are reflected on others. 

 

 

Working of SMTP Server 

 
https://github.com/TheRealPoloMints/Blog/blob/master/Security%20Challenge%20Walkthroughs/Networks%202/untitled.png?raw=true

 

Steps performed by SMTP 

 

    1. The mail user agent, which is either your email client or an external program. connects to the SMTP server of your domain, e.g. smtp.google.com. This initiates the SMTP handshake. This connection works over the SMTP port- which is usually 25. Once these connections have been made and validated, the SMTP session starts. 

 

    The process of sending mail can now begin. The client first submits the sender, and recipient's email address- the body of the email and any attachments, to the server.  

 

    The SMTP server then checks whether the domain name of the recipient and the sender is the same. 

    4. The SMTP server of the sender will make a connection to the recipient's SMTP server before relaying the email. If the recipient's server can't be accessed, or is not available- the Email gets put into an SMTP queue. 

 

    Then, the recipient's SMTP server will verify the incoming email. It does this by checking if the domain and user name have been recognised. The server will then forward the email to the POP or IMAP server, as shown in the diagram above. 

 

    The E-Mail will then show up in the recipient's inbox. 

 

What runs SMTP? 

SMTP Server software is readily available on Windows server platforms, with many other variants of SMTP being available to run on Linux.  

 

 

SMTP ENUMERATION 

 

The SMTP service has two internal commands that allow the enumeration of users: VRFY (confirming the names of valid users) and EXPN (which reveals the actual address of user’s aliases and lists of e-mail (mailing lists). Using these SMTP commands, we can reveal a list of valid users. We will use metasploit "" for enumeration 

 

    Search for all open ports: Port 25 must be open as SMTP 

    Open metasploit : msfconsole 

    Search "smtp_version" 

    We will find auxiliary/scanner/smtp/smtp_version 

    Use this module 

    Show options 

    Set RHOSTS TO <t-ip> and RPORT to 25 

    Run 

    We will find mail name and MTA of smtp 

 
[msf] (Jobs:ø Agents: 0) >> search Matching Modules # Name 0 auxiliary/ scanner/ " smtp_version " Disclosure Date Rank normal Check No Description SMTP Banner Grabber Interact with a module by name or index. For example info 0, use 0 or use auxiliary/ scanner/smtp/smtp_version [msf] (Jobs:ø Agents:0) >> use 0 [msf] (Jobs:ø Agents auxiliary(scanner/smtp/smtp_version) >> show options Module options (auxiliary/ scanner/ smtp/ smtp_version) : Name RHOSTS RPORT THREADS Current Setting Required Description 25 1 yes yes yes The target host(s), see https://docs . me tasploit.com/docs/using-metasploit/basi cs/using-metasploit . html The target port (TCP) The number of concurrent threads (max o ne per host) View the full module info with the info, or info -d command.

 
THREADS 1 yes The number of concurrent threads (max o ne per host) View the full module info with the info, or info -d command. [msf] (Jobs:ø Agents auxiliary(scanner/smtp/smtp_version) >> set RHOSTS 10.10.232.94 RHOSTS 10.10.232.94 [msf] (Jobs:ø Agents auxiliary(scanner/smtp/smtp_version) >> show options Module options (auxiliary/ scanner/ smtp/ smtp_version) : Name RHOSTS RPORT THREADS Current Setting Required Description 10.10.232.94 25 1 yes yes yes The target host(s), see https://docs . me tasploit.com/docs/using-metasploit/basi cs/using-metasploit . html The target port (TCP) The number of concurrent threads (max o ne per host) View the full module info with the info, or info -d command. [msf] (Jobs:ø Agents: 0) auxiliary(scanner/smtp/smtp_version) >> run 10.10.232.94:25 10.10.232.94:25 - 10.10.232.94:25 SMTP 220 polosmtp.home ESMTP Postfix (Ubuntu) - Scanned 1 of 1 hosts (100% complete) Auxiliary module execution completed r (Jobs:ø : 0) auxiliarv( TS

 

    Now brute forcing using smtp_enum module 

 
[msf] (Jobs:ø Agents: 0) >> search Matching Modules # Name 0 auxiliary/ scanner/ " smtp_enum " Disclosure Date Rank normal Check No Description SMTP User Enumeration Utility Interact with a module by name or index. For example info 0, use or use auxiliary/ scanner/smtp/smtp_enum [msf](Jobs:ø Agents:0) >> use 0 [msf] (Jobs:ø Agents auxiliary(scanner/smtp/smtp_enum) >> options Module options (auxiliary/ scanner/ smtp/ smtp_enum) : Name RHOSTS RPORT THREADS UNIXONLY USER FILE Current Setting 25 1 true / usr/ share/ metasploit- framework /data/wordlists/unix users . txt Required yes yes yes yes yes Description The target host(s), see https : / /docs . metasploit . com/doc s/ using-metasploit/basics/using-metasploit . html The target port (TCP) The number of concurrent threads (max one per host) Skip Microsoft bannered servers when testing unix users The file that contains a list of probable users account s. View the full module info with the info, or info -d command.

 

NOTE : we can use wordlist accordlingly 

 
[msf] (Jobs:ø Agents: 0) auxiliary(scanner/smtp/smtp_enum) >> set USER_FILE /usr/share/word1ists/sec1ists/Usernames, top-usernames - shortlist . txt USER_FILE /usr/share/wordlists/seclists/dsernames/top-usernames-shortlist . txt [msf] (Jobs:ø Agents auxiliary(scanner/smtp/smtp_enum) >> options •Module options (auxiliary/ scanner/ smtp/ smtp_enum) : Name RHOSTS RPORT THREADS UNIXONLY USER FILE Current Setting 25 1 true /usr/ share/wordlists/ seclists/U sernames/ top-usernames- shortlis t. txt Required yes yes yes yes yes Description The target host(s), see https : / /docs . metasploit . com/doc s/ using-metasploit/basics/using-metasploit . html The target port (TCP) The number of concurrent threads (max one per host) Skip Microsoft bannered servers when testing unix users The file that contains a list of probable users account s. View the full module info with the info, or info -d command. [msf] (Jobs:ø Agents auxiliary(scanner/smtp/smtp_enum) >> set RHOSTS 10.10.232.94 RHOSTS 10.10.232.94 , [msf] (Jobs: 0 Agents: 0) auxiliary(scanner/smtp/smtp_enum) >> run - 10.10.232.94:25 Banner: 220 polosmtp. home ESMTP Postfix (Ubuntu) 10.10. 232.94: 25 - 10.10.232.94:25 Users found: administrator 10.10. 232.94: 25 - Scanned 1 of 1 hosts (100% complete) 10.10.232.94:25 Auxiliary module execution completed

 

    We have got username : administrator 

 

EXPLOITING SMTP 

 

    Since we have seen that ssh is open in target server or needs to be open. 

    $ : hydra –t 16 –l administrator –P /usr/share/wordlists/rockyou.txt <target_ip> ssh 

    Login into ssh using the username and password. 



 #SMB ENUMERATION

 Docs : https://www.samba.org/samba/docs/current/man-html/smbclient.1.html 

    Server Message Block 

    Network file sharing protocol that allows applications on a computer to read and write files. 

    Request services from server programs in computer network. 

 

Most common ports - 445 ( miscrosoft-ds) and 139 (netbios-ssn) or netbios-ssn both 

    SCAN - nmap -sV -p139,445 <targ_ip> 

    SCAN USING DEFAULT SCRIPTS - nmap -sV -sC -p139,445 <targ_ip> 

    DEFAULT SCRIPTS LOCATE - locate .nse | grep smb 

    SCAN WITH COMMON VULNERABILITIES - nmap -sV -p139,445 --script=vuln* <targ_ip> 

    CHECK SHARES - nmap -sV - -p139,445 --script=smb-enum-shares <targ_ip> 

    ALSO SEARCH FOR USERS - nmap -sV -p139,445 --script=smb-enum-users <targ_ip> 

    TO FIND THE NETBIOS DOMAIN NAME - nbtscan <targ_ip> 

    USE SMBMAP ENUMERATE SAMBA SHARE DRIVES - smbmap -H <targ_ip> (anonymous) 

    smbmap -u indrava -p indrava -H <targ_ip> 

    IF SMBMAP DOESNT WORK, FIND OUT USING SMBCLIENT - smbclient -L <targ_IP> 

    smbclient //<targ_ip>/tmp --option="client min protocol=NT1" ( HERE tmp IS USED AS READ/WRITE ACCESS) 

    SMB LOGIN SUCCESS 

    IF STILL NOT ANY VALUAVLE INFO AVAILABLE, ALWAYS GO FOR ENUM4LINUX - enum4linux -a <targ_ip> 

    IF YOU GET id_rsa(private key) , id_rsa.pub(public key) , authorized keys THEN DOWNLOAD : mget id_rsa , mget id_rsa.public 

    CHANGE PERMISSION : chmod 600 id_rsa 

    IF YOU HAVE ACCESS TO SSH LOGIN : ssh -i id_rsa <username>@<IP>  

    YOU CAN GET USERNAME FROM id_rsa.pub file (maybe) 

 

 

Metasploitable 2 smb exploitation : https://medium.com/@jasonjayjacobs/exploiting-smb-in-metasploitable-2-1ff33fe88bbc 



#RPC SMB FTP ENUMERATION 

RPC is a remote procedure call (or a function call that carries out tasks on a different computer). RPC enumeration is the process of discovering what services are running on what port numbers. Enumerating RPC services can aid in finding information leaks because it allows an attacker to map which systems are most vulnerable, potentially to be exploited at some point. Many people often confuse RPC enumeration with finger pointing or scanning for vulnerabilities. They all involve digging for specific information about the target system, but they don’t work exactly the same way. Finger pointing requires a list of systems to scan, while patching is usually done to the server’s software, so it can be more secure. RPCenumeration, on the other hand, involves finding out what type of information is stored in a given system and where that system falls in the network.  

 
https://media.geeksforgeeks.org/wp-content/uploads/operating-system-remote-call-procedure-working.png

 

 

 

 

SMB  

    Server Message Block 

    Network file sharing protocol that allows applications on a computer to read and write files. 

    Request services from server programs in computer network. 

Most common ports - 445 ( miscrosoft-ds) and 139 (netbios-ssn) or netbios-ssn both 

FTP 

The File Transfer Protocol (FTP) serves as a standard protocol for file transfer across a computer network between a server and a client. It is a plain-text protocol that uses as new line character 0x0d 0x0a so sometimes you need to connect using telnet or nc -C. 

Default Port: 21 

 

PERFORM SMB AND RPC ENUMERATION USING NETSCANTOOLS PRO 

    IN WINDOWS 19 : Open service manager from start 

    The Server Manager main window appears. By default, Dashboard will be selected; click Add roles and features. 

    The Add Roles and Features Wizard window appears. Click Next here and in the Installation Type and Server Selection wizards. 

    The Server Roles section appears. Expand File and Storage Services and select the checkbox for Server for NFS under the File and iSCSI Services option, as shown in the screenshot. Click Next. 

Note: In the Add features that are required for Server for NFS? pop-up window, click the Add Features button. 

    In the Features section, click Next. The Confirmation section appears; click Install to install the selected features. 

    The features begin installing, with progress shown by the Feature installation status bar. When installation completes, click Close. 

    Switch to the Windows 11 virtual machine. 

    Navigate to E:\CEH-Tools\CEHv12 Module 03 Scanning Networks\Scanning Tools\NetScanTools Pro and double-click nstp11demo.exe. 

    Note: If a User Account Control pop-up appears, click Yes 

    The Setup - NetScanTools Pro Demo window appears, click Next and follow the wizard-driven installation steps to install NetScanTools Pro. 

Note: If a WinPcap 4.1.3 Setup pop-up appears, click Cancel.  

    In the Completing the NetScanTools Pro Demo Setup Wizard, ensure that Launch NetScanTools Pro Demo is checked and click Finish. 

    The Reminder window appears; if you are using a demo version of NetScanTools Pro, click the Start the DEMO button. 

    A DEMO Version pop-up appears; click the Start NetScanTools Pro Demo... button.  

    The NetScanTools Pro main window appears, as shown in the screenshot.  

    In the left pane, under the Manual Tools (all) section, scroll down and click the SMB Scanner option, as shown in the screenshot. 

Note: If a dialog box appears explaining the tool, click OK.  

    In the right pane, click the Start SMB Scanner (external App) button. 

Note: If the Demo Version Message pop-up appears, click OK. In the Reminder window, click Start the DEMO. 

    The SMB Scanner window appears; click the Edit Target List button. 

    The Edit Target List window appears. In the Hostname or IPv4 Address field, enter the target IP address (10.10.1.19, in this example). Click the Add to List button to add the target IP address to Target List 

    Similarly, add another target IP address (10.10.1.22, in this example) to Target List and click OK. 

Note: In this task, we are targeting the Windows Server 2019 (10.10.1.19) and Windows Server 2022 (10.10.1.22) machines. 

    Now, click Edit Share Login Credentials to add credentials to access the target systems. 

    The Login Credentials List for Share Checking window appears. Enter Administrator and Pa$$w0rd in the Username and Password fields, respectively. Click Add to List to add the credentials to the list and click OK. 

Note: In this task, we are using the login credentials for the Windows Server 2019 and Windows Server 2022 machines to understand the tool. In real-time, attackers may add a list of login credentials by which they can log in to the target machines and obtain the required SMB share information. 

    In the SMB Scanner window, click the Get SMB Versions button. 

    Once the scan is complete, the result appears, displaying information such as the NetBIOS Name, DNS Name, SMB versions, and Shares for each target IP address. 

    Right-click on any of the machines (in this example, we will use 10.10.1.19) and click View Shares from the available options. 

    The Shares for 10.10.1.19 window appears, displaying detailed information about shared files such as Share Name, Type, Remark, Path, Permissions, and Credentials Used. Close the Shares for 10.10.1.19 window. 

Note: By using this information, attackers can perform various attacks such as SMB relay attacks and brute-force attacks on the target system. 

    You can view the details of the shared files for the target IP address 10.10.1.22 in the same way. 

    In the left pane, under the Manual Tools (all) section, scroll down and click the *nix RPC Info option, as shown in the screenshot. 

Note: If a dialog box appears explaining the tool, click OK.  

    In the Target Hostname or IPv4 Address field enter 10.10.1.19 and click Dump Portmap. 

    The result appears displaying the RPC info of the target machine (Windows Server 2019), as shown in the screenshot. 

Note: Enumerating RPC endpoints enables attackers to identify any vulnerable services on these service ports. In networks protected by firewalls and other security establishments, this portmapper is often filtered. Therefore, attackers scan wide port ranges to identify RPC services that are open to direct attack.  

 

RPC, SMB, AND FTP ENUMERATION USING NMAP 

    WIN 19 : Click on the File Explorer icon at the bottom of Desktop. In the File Explorer window, right-click on Local Disk (C:) and click New → Folder. 

    A New Folder appears. Rename it to FTP-Site Data, as shown in the screenshot. 

    Close the window and click on the Type here to search icon at the bottom of the Desktop. Type iis. In the search results, click on Internet Information Services Manager (IIS) Manager, as shown in the screenshot. 

    In the Internet Information Services (IIS) Manager window, click to expand SERVER2019 (SERVER2019\Administrator) in the left pane. Right-click Sites, and then click Add FTP Site.... 

    In the Add FTP Site window, type CEH.com in the FTP site name field. In the Physical path field, click on the icon. In the Browse For Folder window, click Local Disk (C:) and FTP-Site Data, and then click OK. 

    In the Add FTP Site window, check the entered details and click Next. 

    The Binding and SSL Settings wizard appears. Under the Binding section, in the IP Address field, click the drop-down icon and select 10.10.1.19. Under the SSL section, select the No SSL radio button and click Next. 

    The Authentication and Authorization Information wizard appears. In the Allow access to section, select All users from the drop-down list. In the Permissions section, select both the Read and Write options and click Finish. 

    The Internet Information Services (IIS) Manager window appears with a newly added FTP site (CEH.com) in the left pane. Click the Site node in the left pane and note that the Status is Started (ftp), as shown in the screenshot. 

    PARROT OS : nmap -p 21 [Target IP Address]  

    nmap -T4 -A [Target IP Address]  

    The scan result appears, displaying information regarding open ports, services along with their versions. You can observe the RPC service and NFS service running on the ports 111 and 2049, respectively, as shown in the screenshot. 

    nmap -p [Target Port] -A [Target IP Address] (in this example, the target port is 445 and the target IP address is 10.10.1.19) and press Enter 

    nmap -p [Target Port] -A [Target IP Address] (in this example, the target port is 21 and target IP address is 10.10.1.19) and press Enter 

    Using this information, attacker can further identify any vulnerable service running on the open service ports and exploit them to launch attacks. 



# CEH Skill Check
#Skill Check 1 

Q1. You are performing reconnaissance for CEHORG and has been assigned a task to find out the physical location of one of their webservers hosting www.certifiedhacker.com. What are the GEO Coordinates of the webserver? Note: Provide answer as Latitude, Longitude. (Format: NN.NNN, *NN.NNN) 

A. Go to IP Tracker website (37.751, -97.822) 

 

Q2. Identify if the website www.certifiedhacker.com allows DNS zone transfer. (Yes/No) (Format: Aa) 

A. Step 1: Find name server using dig or nmap : dig ns www.certifiedhacker.com or nmap -sC -A <> 

Step 2 : dig @ns1.bluehost.com www.certifiedhacker.com axfr (Says failed)  

Answer : No ( We found the IP of the domain : 162.241.216.11) 

 

Q3. Identify the number of live machines in 172.16.0.0/24 subnet. 

A. (3)We will use UDP PING scan : nmap -sn -PU 172.16.0.0/24.  

 

Q4. Find the IP address of the machine which has port 21 open. Note: Target network 172.16.0.0/24 

A. (172.16.0.12) nmap 172.16.0.0/24 

 

Q5. Find the IP address of the Domain Controller machine in 10.10.10.0/24. 

A.(10.10.10.25) First we do nmap -sn 10.10.10.0/24. We can see 2 hosts are present. Now we will go to netbios enumerator in windows and it will show 10.10.10.25. So this IP is the answer. 

 

Q6. Perform a host discovery scanning and identify the NetBIOS name of the host at 10.10.10.25. 

A. (ADMINDEPT) nmap -sV -v --script nbstat.nse 10.10.10.25 

 

Q7. Perform an intense scan on 10.10.10.25 and find out the FQDN of the machine in the network 

A.(AdminDept.CEHORG.com) nmap -A 10.10.10.25 

 

Q8. What is the DNS Computer Name of the Domain Controller? 

A.(AdminDept.CEHORG.com) nmap -A 10.10.10.25 

 

Q9. While performing a security assessment against the CEHORG network, you came to know that one machine in the network is running OpenSSH and is vulnerable. Identify the version of the OpenSSH running on the machine. Note: Target network 192.168.0.0/24 

A.(8.9p1) nmap 192.168.0.0/24 -sV. Then we will find a machine with IP 192.168.0.55 has openSSH 

 

Q10. During a security assessment, it was found that a server was hosting a website that was susceptible to blind SQL injection attacks. Further investigation revealed that the underlying database management system of the site was MySQL. Determine the machine OS that hosted the database 

A.(Ubuntu) nmap -A -O 192.168.0.55 

 

Q11. Perform LDAP enumeration on the target network and find out how many user accounts are associated with the domain.  

A.(8) enum4linux 10.10.10.25 

 

Q12. Perform an LDAP Search on the Domain Controller machine and find out the version of the LDAP protocol 

A.(LDAPv3) ldapsearch -h 10.10.10.25 -x -b “DC=CEHORG,DC=com” 

 

Q13. What is the IP address of the machine that has NFS service enabled? Note: Target network 192.168.0.0/24 

A.(192.168.0.51) nmap 192.168.0.0/24 

 

Q14. Perform a DNS enumeration on www.certifiedhacker.com and find out the name servers used by the domain 

A(ns1.bluehost.com, ns2.bluehost.com) dig ns www.certifiedhacker.com 

 

Q15. Find the IP address of the machine running SMTP service on the 192.168.0.0/24 network 

A.(192.168.0.51) nmap 192.168.0.0/24 

 

Q16. Perform an SMB Enumeration on 192.168.0.51 and check whether the Message signing feature is enabled or disabled 

A.(Yes) nmap -sV -sC 192.168.0.51. It will say message signing enables but not required 

 

Q17. Perform a vulnerability research on CVE-2022-30171 and find out the base score and impact of the vulnerability 

A.(5.5 Medium) Google search CVE-2022-30171 

 

Q18. Perform vulnerability scanning for the domain controller using OpenVAS and identify the number of vulnerabilities with severity level as "medium" 

A.(3) Open Vas from Pentesting → Vulnerability Analysis → Openvas - Greenbone → Start Greenbone Vulnerability Manager Service. Use 

credentials as admin and password. Go to task > new task. Go to scans > vulnerabilities to find the desired output. 

 

Q19. Perform vulnerability scanning for the webserver hosting movies.cehorg.com using OpenVAS and identify the severity level of RPC vulnerability 

A.(5) Find out IP using nmap then the same steps. Pentesting → Vulnerability Analysis → Openvas - Greenbone → Start Greenbone Vulnerability Manager Service. Usecredentials as admin and password. Go to task > new task. Go to scans > vulnerabilities to find the desired output. 

 

Q20. Perform vulnerability scanning for the Linux host in the 172.16.0.0/24 network using OpenVAS and find the number of vulnerabilities with severity level as medium.  

A.(7) Pentesting → Vulnerability Analysis → Openvas - Greenbone → Start Greenbone Vulnerability Manager Service. Usecredentials as admin and password. Go to task > new task. Go to scans > vulnerabilities to find the desired output. 



#Skill Check 2 

Q1. You are assigned a task to crack the NTLM password hashes captured by the internal security team. The password hash has been stored in the Documents folder of the Parrot Security console machine. What is the password of user James? (Format: aaaaaa) 

A. Go to the hashes file and then in terminal : john /home/attacker/Documents/hashes.txt --format=NT (ANS:qwerty) 

 

Q2. You are assigned a task to crack the NTLM password hashes captured by the internal security team. The password hash has been stored in the Documents folder of the Parrot Security console machine. What is the password of user Jones? (Format: NNNNNNNN) 

A. Same as above (ANS:12345678) 

 

Q3. You have been given a task to audit the passwords of a server present in CEHORG network. Find out the password of the user Adam and submit it 

A.(password4) From engage 1 , we got the IP of FQDN. So using l0phtcrack on 10.10.10.25 and guess/find out. 

 

Q8. You are a malware analyst working for CEHORG. During your assessment within your organisation's network, you found a malware face.exe. The malware is extracted and placed at C:\Users\Admin\Documents in the EH Workstation – 2 machine. Analyze the malware and find out the File pos for KERNEL32.dll text 

A.(DC14) Windows : Go to tools > malware analysis > static malware analysis > string searching > binText (open it). Browse for the exe malware using advanced option. In the find bar write kernel32. 

 

Q9. Analyze an ELF executable (Sample-ELF) file placed at C:\Users\Admin\Documents in the EH Workstation – 2 machines to determine the CPU Architecture it was built for 

A.(AARCH64) Open die.exe from malware analysis > static malware analysis > packaging and obfsucation > die. Open the elf file. 

 

Q10. CEHORG has assigned you with analysing the snapshot of the operating system registry and perform the further steps as part of dynamic analysis and find out the whether the driver packages registry is changed. Give your response as Yes/No. 

A.(Yes) Open soft perfect network scanner from snmp enumeration and install it. Then open Malware Analysis Tools\Dynamic Malware Analysis Tools\Registry Monitoring Tools\Reg Organizer. double-click reg-organizer-setup.exe. Click registry snapshots from tools. We will see changed registry. 

 

Q11. Perform windows service monitoring and find out the service type associated with display name "afunix".  

A. (Driver) Go to E:\CEH-Tools\CEHv12 Module 07 Malware Threats\Malware Analysis Tools\Dynamic Malware Analysis Tools\Windows Services Monitoring Tools\Windows Service Manager (SrvMan)\x64. Open the srvman.exe file. 

 

Q12. Use Yersinia on the “EH Workstation – 1” (Parrot Security) machine to perform the DHCP starvation attack. Analyze the network traffic generated during the attack and find the Transaction ID of the DHCP Discover packets. 

A.(0x643c9869) Parrot : Open wireshark and double click on eth0. Go to terminal type yersinia -I and press h for help, q for quit. Press F2 for DHCP mode and then press x and 1 to start DHCP or Ddos attack. After some time close it then open wireshark and we will find out.  

 

Q13. CEHORG suspects a possible sniffing attack on a machine in its network. The organization has retained the network traffic data for the session and stored it in the Documents folder in EH Workstation – 2 (Windows 11) machine as sniffsession.pcap. You have been assigned a task to analyze and find out the protocol used for sniffing on its network. 

A.(ARP) View it in wireshark and scroll thoroughly.  

 

Q14. As an ethical hacker, you are tasked to analyze the traffic capture file webtraffic.pcapng. Find out the packet's id that uses ICMP protocol to communicate. Note: The webtraffic.pcapng file is located at C:\Users\Administrator\Documents\ in the Documents folder on EH Workstation – 2 (Windows 11) machine. 

A.(0xfc83) Use wireshark and ID will be directly seen on the info area 

 

Q15. CEHORG has found that one of its web application movies.cehorg.com running on its network is leaking credentials in plain text. You have been assigned a task of analysing the movies.pcap file and find out the leaked credentials. Note: The movies.pcapng file is located at C:\Users\Administrator\Documents\ in the Documents folder on EH Workstation – 2 (Windows 11) machine. Make a note of the credentials obtained in this flag, it will be used in the Part 4 of CEH Skill Check. 

A.(Jason/welcome) Open using wireshark. On filter write http.request.method == POST. We can find under POST methods. HTML form URL encoding. 

 

Q16. An attacker has created a custom UDP packet and sent it to one of the machines in the CEHORG. You have been given a task to study the ""CustomUDP.pcapng"" file and find the data size of the UDP packet (in bytes). Note: The CustomUDP.pcapng file is located at C:\Users\Administrator\Documents\ in the Documents folder on EH Workstation – 2 (Windows 11) machine.  

A.(600) Open using wireshark and we can find Len=600 

 

Q17. A denial-of-service attack has been launched on a target machine in the CEHORG network. A network session file "DoS.pcapng" has been captured and stored in the Documents folder of the EH Workstation - 2 machine. Find the IP address of the attacker's machine. 

A.(192.168.0.51) Open using wireshark and we will find out many SYN , SYN-ACK , ACK from a source. 

 

Q18. CEHORG hosts a datacenter for its bussiness clients. While analyzing the network traffic it was observed that there was a huge surge of incoming traffic from multiple sources. You are given a task to analyze and study the DDoS.pcap file. The captured network session (DDoS.pcapng) is stored in the Documents folder of the EH Workstation -2 machine. Determine the number of machines that were used to initiate the attack. 

A.(3) Go to wireshark > statistics > endpoints 




#Skill Check 3 

Q1. CEHORG suspects of a possible session hijacking attack on a machine in its network. The organisation has retained the network traffic data for the session at C:\Users\Admin\Documents in the EH Workstation – 2 as sniffsession.pcap. You have been assigned a task to perform an analysis and find out the protocol that has been used for sniffing on its network. 

A.(ARP) Check for ARP packets in wireshark. 

 

Q2. You have been assigned a task to perform a clickjacking test on www.certifiedhacker.com that the CEHORG members widely use. Find out whether the site is vulnerable to clickjacking. 

A.(Yes) Go to clickjacking poc html in google (https://clickjacker.io/making-clickjacking-poc) copy the code and open in code editor in parrot. Change iframe attribute to the website link and save as html file. Open the file in firefox if the site opens in image then yes clickjacking attack. 

 

Q3. Perform an HTTP-recon on www.certifiedhacker.com and find out the version of Nginx used by the web server. 

A.(1.21.6) Go to httprecon tool in windows ceh tools and give the site and analyze 

 

Q4. An FTP site is hosted on a machine in the CEHORG network. Crack the FTP credentials, obtain the “flag.txt” file and determine the content in the file. 

A.(Secrets@FTP) Find the subnet from opening openvas and search for open ftp port 21 from all 3 subnets. We will find IP with 172.16.0.12 has open ftp port. We will brute force by using : hydra -L /home/attacker/Desktop/"cehv12 hacking web servers"/Wordlists/Usernames.txt -P /home/attacker/Desktop/"cehv12 hacking web servers"/Wordlists/Passwords.txt ftp://172.16.0.12. We will get Martin with password qwerty1234. Log in using ftp 172.16.0.12. Then get flag.txt. 

 

Q5. Perform Banner grabbing on the web application movies.cehorg.com and find out the ETag of the respective target machine. 

A.("8d13646dbb9bd61:0") Parrot : telnet movies.cehorg.com 80 then type GET / HTTP/1.0 and press enter 2 times. Put the whole in inverted commas. 

 

Q6.Identify the Content Management System used by www.cehorg.com. 

A.(WordPress) parrot : whatweb -v www.cehorg.com, We will find many wordpress keywords as this is the Content Management System 

 

Q7. Perform web application reconnaissance on movies.cehorg.com and find out the HTTP server used by the web application. 

A.(Microsoft-IIS/10.0) Windows : Go to tools > hacking web servers > ID serve tool and paste the site. OR Parrot : telnet movies.cehorg.com 80 then type GET / HTTP/1.0 press enter two times. 

 

Q8. Perform Web Crawling on the web application movies.cehorg.com and identify the number of live png files in images folder 

A.(6). Owasp ZAP 

 

Q9. Identify the load balancing service used by eccouncil.org. 

A.(cloudflare) Parrot : lbd eccouncil.org 

 

Q10. Perform a bruteforce attack on www.cehorg.com and find the password of user adam. 

A.(orange1234) Burp Suite brute force attack 

 

Q.11 Perform parameter tampering on movies.cehorg.com and find out the user for id 1003. 

A.(Linda) Login to the website using Jason/welcome cred and then go to profile and change id. 

 

Q12. Perform a SQL Injection attack on movies.cehorg.com and find out the number of users available in the database. Use Jason/welcome as login credentials.  

A.(9) Go to website and login then go to profile. Find out cookie from inspect>console:document.cookie. In parrot : sqlmap -u “URL” --cookie="COPIED COOKIE" --dbs. Then enumerate tables using same command , add --tables. Then find out user profiles using sqlmap -u “URL” --cookie="COPIED COOKIE" --dbs -T User_Profiles --dump. 

 

Q13. Perform XSS vulnerability test on www.cehorg.com and identify whether the application is vulnerable to attack or not. 

A.(No) Go to pwnxss directory : python3 pwnxss -u <URL>, Click and check on some links of GET parameter. Or we can also find out using parameter tampering. 

 

Q14. Perform command injection attack on 10.10.10.25 and find out how many user accounts are registered with the machine. Note: Exclude admin/Guest user 

A.(8) Go to 10.10.10.25:8080/DVWA. Type the Username/Password as gordonb/abc123 or admin/password. Click the Login button.Then set security to low and go to command injection area. Type | net user to get the user list. 

 

Q15. A file named Hash.txt has been uploaded through DVWA (http://10.10.10.25:8080/DVWA). The file is located in the directory mentioned below. Access the file and crack the MD5 hash to reveal the original message; enter the content after cracking the hash. You can log into the DVWA using the following credentials. Note: Username- admin; Password- password Path: C:\wamp64\www\DVWA\hackable\uploads\Hash.txt Hint: Use “type” command to view the file. Use the following link to decrypt the hash- https://hashes.com/en/decrypt/hash  

A.(Cr@ck3d) Go to the given link > command injection part. Type : | type C:\wamp64\www\DVWA\hackable\uploads\Hash.txt. Put the hash into hashes website to get the answer. 

 

Q16. You have identified a vulnerable web application on a Linux server at port 8080. Exploit the web application vulnerability, gain access to the server and enter the content of RootFlag.txt as the answer. 

A.(Ch@mp2022) Use log4j vulnerability  



#Skill Check 4 

Q1. In attacker has intruded into the CEHORG network with malicious intent. He has identified a vulnerability in a machine. He has encoded the machine's IP address and left it in the database. While auditing the database, the encoded file was identified by the 

database admin. Decode the EncodedFile.txt file in the Document folder in the "EH Workstation - 2" machine and enter the IP address as the answer. (Hint: Password to decode the file is Pa$$w0rd) 

A.(10.10.10.31) Use BCTextEncoder in windows, copy the entire text in the decode section and we will see the output in encoded section. Give the password as necessary 

 

Q2. The Access code of an employee was stolen from the CEHORG database. The attacker has encrypted the file using the Advance Encryption Package. You have been assigned a task to decrypt the file; the organization has retained the cipher file "AccessCode.docx.aes" in the Document folder in the ""EH Workstation - 2" machine. Determine the access code by decrypting the file. Hint: Use 'qwerty" as the decryption password. Note: Advanced Encryption Package is available at E:\CEH-Tools\CEHv12 

Module 20 Cryptography\Cryptography Tools. 

A.(ECC-CSC-2006) Use the advanced Encryption Package tool and open the given document. 

 

Q3. A VeraCrypt volume file "secret" is stored on the Document folder in the "EH Workstation-2" machine. You are an ethical hacker working with CEHORG; you have been tasked to decrypt the encrypted volume and determine the number of files stored in the volume. (Hint: Password: test) 

A.(6)Open veracrypt tool, select a drive , say L and then select the file from given location do mount and then give password. Go to the newly created volume and select the no of files present there. 

 

Q4. You have received a folder named "Archive" from a vendor. You suspect that someone might have tampered with the files during transmission. The Original hashes of the files have been sent by the sender separately and are stored in a file named FileHashes.txt stored in the Document folder in the "EH Workstation - 2" machine. Your task is to check the integrity of the files by comparing the MD5 hashes. Compare the hash values and determine the file name that has been tampered with. Note: Exclude the file extension in the answer field. The answer is case-sensitive. 

A.(Quotes) Open the tool md5 calculator, compare which one has changed by adding. 

 

Q5. CEHORG hosts multiple loT devices and sensors to manage its supply chain fleet. You are assinged a task to examine the file "IOT Traffic.pcapng" located in the Home directory of the root user in the "EH Workstation - 1" machine. Analyze the packet and find the topic 

of the message sent to the sensor. 

A.(Fleet_Count) Go to parrot, open wireshark and select the pcapng file, filter MQTT protocol and we will find the answer. 

 

Q6. An employee in CEHORG has secretly acquired Confidential access ID through an application from the company. He has saved this information on the Downloads folder of his Android mobile phone. You have been assigned a task as an ethical hacker to access the file and delete it covertly. Enter the account information present in the file. Note: Only provide the numeric values in the answer field. 

A.(80099889) Android ADB port range – 5555 to 5585, we need to scan first. Need to check all the subnets. Nmap  –p5555 172.16.0.0/24. We will find port 5555 open in 172.16.0.21. Go to phonesploit tool directory in parrot > python phonesploit.py > type 172.16.0.21 > type 4   > cd /sdcard/Downloads and then cat confidential.txt 

 

Q7. The mobile device of an employee in CEHORG has been hacked by the hacker to perform DoS attack on one of the server in company network. You are assigned to analyse 'Andro.pcapng" located in Documents directory of EH workstation-2 and identify the severity level of the attack. (Note: perform deep down Expert Info analysis) 

A.(Warning) Open the file in wireshark and then select the android ip = 172.16.0.21 go to Analyse tab then to expert information. We will see warning present there. 

 

Q8. An attacker has hacked one of the employees android device in CEHORG and initiated LOIC attack from the device. You are an ethical hacker who had obtained a screenshot of the attack using a background application. Obtain the screenshot of the attack using PhoneSploit from the attacked mobile device and determine the targeted machine IP along with send method. 

A.(172.16.0.11/HTTP) Go to phonesploit main menu and select option 9 (select folder phone to pc) > /sdcard/DCIM. In parrot terminal we will find DCIM folder in maybe phonesploit folder. On opening the picture, we will get 172.16.0.11 

 

Q9. An attacker installed a malicious mobile application 'AntiMalwarescanner.apk' on the victims android device which is located in EH workstation-2 documents folder. You are assigned a task to perform security audit on the mobile application and find out whether the application using permission to Read-call-logs. 

A.(Yes)  

 

Q10. An ex-employee of CEHORG is suspected to be performing insider attack. You are assigned a task to attain KEYCODE-75 used in the employees' mobile phone. Note: use option p in PhoneSploit for next page. 

A.(APOSTROPHE ) From phonesploit main menu type p > type 24 (keycode if given) > We will see KEYCODE_APOSTROPHE on 75 number. 

 

Q11. CEHORG hosts multiple IOT devices and sensors to manage its supply chain fleet. You are assinged a task to examine the file "IOT Traffic.pcapng" located in the Home directory of the root user in the "EH Workstation - 1" machine. Analyze the packet and find the topic 

of the message sent to the sensor. 

A.(Fleet_Count) Same as question 5 

 

Q12. CEHORG hosts multiple IOT devices and network sensors to manage its IT-department. You are assigned a task to examine the file "NetworkNS_Traffic.pcapng" located in the Documents folder of the user in the "EH Workstation - 2" machine. Analyze the packet 

and find the alert message sent to the sensor. 

A.(Data Bre@ch @lert) Open the pcapng in wireshark give mqtt in the filter. Click on High_Ber packet. Go to message part and then we will find the answer in the bottom hexadecimal area. 

 

Q13. An attacker had sent a message 166.150.247.183/US to the victim. You are assigned to perform footprinting using shodan.io in order to identify whether the message belongs to SCADA/ICS/loT systems in US. 

A.(IoT) Go to shodan website, we will get IOT as answer. 

 

Q14. An attacker had sent a file cryt-128-06encr.hex containing ransom file password, which is located in documents folder of EH-workstation-2. You are assigned a task to decrypt the file using cryp tool. Perform cryptanalysis, Identify the algorithm used for file encryption and hidden text. Note: check filename for key length and hex characters. 

A.() Open cryp tool , open the given file but maybe the question is complete for here. 



