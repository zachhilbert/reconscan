#!/usr/bin/env python

###############################################################################################################
## [Title]: reconscan.py -- a recon/enumeration script
## [Author]: Mike Czumak (T_v3rn1x) -- @SecuritySift
##-------------------------------------------------------------------------------------------------------------
## [Details]: 
## This script is intended to be executed remotely against a list of IPs to enumerate discovered services such 
## as smb, smtp, snmp, ftp and other. 
##-------------------------------------------------------------------------------------------------------------
## [Warning]:
## This script comes as-is with no promise of functionality or accuracy.  I strictly wrote it for personal use
## I have no plans to maintain updates, I did not write it to be efficient and in some cases you may find the 
## functions may not produce the desired results so use at your own risk/discretion. I wrote this script to 
## target machines in a lab environment so please only use it against systems for which you have permission!!  
##-------------------------------------------------------------------------------------------------------------   
## [Modification, Distribution, and Attribution]:
## You are free to modify and/or distribute this script as you wish.  I only ask that you maintain original
## author attribution and not attempt to sell it or incorporate it into any commercial offering (as if it's 
## worth anything anyway :)
###############################################################################################################
import socket
import argparse
import subprocess
import multiprocessing
import os


global args
args = None

def multProc(targetin, scanip, port, OUTDIR):
    p = multiprocessing.Process(target=targetin, args=(scanip,port,OUTDIR))
    p.start()
    return

def dnsEnum(ip_address, port, OUTDIR):
    print "INFO: Detected DNS on " + ip_address + ":" + port
    if port.strip() != "53":
        return

    HOSTNAME = "nmblookup -A %s | grep '<00>' | grep -v '<GROUP>' | cut -d' ' -f1" % (ip_address)# grab the hostname
    host = subprocess.check_output(HOSTNAME, shell=True).strip()
    print "INFO: Attempting Domain Transfer on " + host
    ZT = "dig @%s.thinc.local thinc.local axfr" % (host)
    ztresults = subprocess.check_output(ZT, shell=True)
    if "failed" in ztresults:
        print "INFO: Zone Transfer failed for " + host
    else:
        print "[*] Zone Transfer successful for " + host + "(" + ip_address + ")!!! [see output file]"
        outfile = os.path.join(OUTDIR, ip_address+ "_zonetransfer.txt")
        dnsf = open(outfile, "w")
        dnsf.write(ztresults)
        dnsf.close

    return

def httpEnum(ip_address, port, OUTDIR):
    if 'http' in args.only or not len(args.only):
        print "INFO: Detected http on " + ip_address + ":" + port
        print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
        HTTPSCAN = ('nmap -sV -Pn -vv -p %s '
                    '--script=http-vhosts,http-userdir-enum,http-apache-negotiation,'
                    'http-backup-finder,http-config-backup,http-default-accounts,'
                    'http-email-harvest,http-methods,http-method-tamper,http-passwd,http-robots.txt '
                    '-oA %s_http %s') % (port, os.path.join(OUTDIR, ip_address), ip_address)
        nmap_file = '%s_http.nmap' % os.path.join(OUTDIR, ip_address)
        if not os.path.exists(nmap_file):
            subprocess.check_output(HTTPSCAN, shell=True)

    if 'dirb' not in args.only and len(args.only):
        return
    url = 'http://%s:%s' % (ip_address, port)
    outf = os.path.join(OUTDIR, ip_address+"_dirb_")
    folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]

    found = []
    print "INFO: Starting dirb scan for " + url
    for folder in folders:
        for filename in os.listdir(folder):
            if 'big' in filename or os.path.isdir(os.path.join(folder, filename)):
                continue
            outfile = " -o " + outf + filename
            if os.path.exists(outfile):
                print 'dirb scan already run'
                return

            DIRBSCAN = "dirb %s %s/%s %s -S -r" % (url, folder, filename, outfile)
            try:
                results = subprocess.check_output(DIRBSCAN, shell=True)
                resultarr = results.split("\n")
                for line in resultarr:
                    if "+" in line and line not in found:
                        found.append(line)
            except:
                pass
    try:
        if found[0] != "":
            print "[*] Dirb found the following items..."
            for item in found:
                print "   " + item
    except:
        print "INFO: No items found during dirb scan of " + url		

    return

def httpsEnum(ip_address, port, OUTDIR):
    if 'https' in args.only or not len(args.only):
        print "INFO: Detected https on " + ip_address + ":" + port
        print "INFO: Performing nmap web script scan for " + ip_address + ":" + port    
        HTTPSCANS = ('nmap -sV -Pn -vv -p %s '
                     '--script=http-vhosts,http-userdir-enum,http-apache-negotiation,http-backup-finder,'
                     'http-config-backup,http-default-accounts,http-email-harvest,http-methods,'
                     'http-method-tamper,http-passwd,http-robots.txt '
                     '-oA %s_https %s') % (port, os.path.join(OUTDIR, ip_address), ip_address)
        nmap_file = '%s_https.nmap' % os.path.join(OUTDIR, ip_address)
        if not os.path.exists(nmap_file):
            subprocess.check_output(HTTPSCANS, shell=True)
    
    if 'dirb' not in args.only and len(args.only):
        return
    url = 'https://%s:%s' % (ip_address, port)
    outf = os.path.join(OUTDIR, ip_address+"_dirbs_")
    folders = ["/usr/share/dirb/wordlists", "/usr/share/dirb/wordlists/vulns"]

    found = []
    print "INFO: Starting dirb scan for " + url
    for folder in folders:
        for filename in os.listdir(folder):
            if 'big' in filename or os.path.isdir(os.path.join(folder, filename)):
                continue
            outfile = " -o " + outf + filename
            if os.path.exists(outfile):
                print 'dirb scan already run'
                return

            DIRBSCAN = "dirb %s %s/%s %s -S -r" % (url, folder, filename, outfile)
            try:
                results = subprocess.check_output(DIRBSCAN, shell=True)
                resultarr = results.split("\n")
                for line in resultarr:
                    if "+" in line and line not in found:
                        found.append(line)
            except:
                pass

    try:
        if found[0] != "":
            print "[*] Dirb found the following items..."
            for item in found:
                print "   " + item
    except:
        print "INFO: No items found during dirb scan of " + url		
    return

def mssqlEnum(ip_address, port, OUTDIR):
    print "INFO: Detected MS-SQL on " + ip_address + ":" + port
    print "INFO: Performing nmap mssql script scan for " + ip_address + ":" + port    
    MSSQLSCAN = ('nmap -vv -sV -Pn -p %s '
                 '--script=ms-sql-info,ms-sql-config,ms-sql-dump-hashes '
                 '--script-args=mssql.instance-port=1433,smsql.username-sa,mssql.password-sa '
                 '-oA %s_mssql %s') % (port, os.path.join(OUTDIR, ip_address), ip_address)
    subprocess.check_output(MSSQLSCAN, shell=True)

def sshEnum(ip_address, port, OUTDIR):
    if not args.ssh:
        return
    print "INFO: Detected SSH on " + ip_address + ":" + port
    print "INFO: Performing hydra ssh scan against " + ip_address 
    HYDRA = "hydra -L userlist -P passwordlist -f -o %s_sshhydra.txt -u %s -s %s ssh" % (os.path.join(OUTDIR, ip_address), ip_address, port)
    filename = os.path.join(OUTDIR, ip_address+'_sshresults.txt')
    f = open(filename, 'w')
    try:
        results = subprocess.check_output(HYDRA, shell=True)
        resultarr = results.split("\n")
        for result in resultarr:
            if "login:" in result:
                print "[*] Valid ssh credentials found: " + result
                f.write("[*] Valid ssh credentials found: " + result)
    except:
        print "INFO: No valid ssh credentials found"

    f.close()
    return

def snmpEnum(ip_address, port, OUTDIR):
    print "INFO: Detected snmp on " + ip_address + ":" + port

    snmpdetect = False
    ONESIXONESCAN = "onesixtyone -c community %s" % (ip_address)
    results = subprocess.check_output(ONESIXONESCAN, shell=True).strip()

    if results != "":
        if "Windows" in results:
            results = results.split("Software: ")[1]
            snmpdetect = True
        elif "Linux" in results:
            results = results.split("[public] ")[1]
            snmpdetect = True
        if snmpdetect:
            filename = os.path.join(OUTDIR, '%s_snmprunning' % ip_address)
            f = open(filename, 'w')
            print "[*] SNMP running on " + ip_address + "; OS Detect: " + results
            f.write("[*] SNMP running on " + ip_address + "; OS Detect: " + results +'\n')
            f.close()
            SNMPWALK = "snmpwalk -c public -v1 %s 1 > %s_snmpwalk.txt" % (ip_address, os.path.join(OUTDIR, ip_address))
            results = subprocess.check_output(SNMPWALK, shell=True)

    NMAPSCAN = ('nmap -vv -sV -sU -Pn -p 161,162 '
                '--script=snmp-netstat,snmp-processes %s -oA %s_snmprecon') % (ip_address, os.path.join(OUTDIR, ip_address))
    results = subprocess.check_output(NMAPSCAN, shell=True)
    return

def smtpEnum(ip_address, port, OUTDIR):
    print "INFO: Detected smtp on " + ip_address + ":" + port
    print "INFO: Trying SMTP Enum on " + ip_address

    port = int(port)
    names = open('userlist', 'r')
    filename = os.path.join(OUTDIR, 'smtpenum_%s' % ip_address)
    f = open(filename, 'w')
    for name in names:
        s=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((ip_address, port))
        banner=s.recv(1024)
        s.send('HELO test@test.org \r\n')
        result= s.recv(1024)
        s.send('VRFY ' + name.strip() + '\r\n')
        result=s.recv(1024)
        s.close()
        if ("not implemented" in result) or ("disallowed" in result):
            print "INFO: VRFY Command not implemented on " + ip_address
            return
        if (("250" in result) or ("252" in result) and ("Cannot VRFY" not in result)):
            print "[*] SMTP VRFY Account found on " + ip_address + ": " + name.strip()
            f.write("[*] SMTP VRFY Account found on " + ip_address + ": " + name.strip()+'\n')
    names.close()
    f.close()

    return

def smbEnum(ip_address, port, OUTDIR):
    print "INFO: Detected SMB on " + ip_address + ":" + port
    if port.strip() != "445":
        return

    if 'smb' in args.only or not len(args.only):
        print "INFO: Detected SMB on " + ip_address + ":" + port
        print "INFO: Performing nmap web script scan for " + ip_address + ":" + port
        SMBSCAN = ('nmap --script=smb-check-vulns --script-args=unsafe=1 -vv -p %s '
                    '-oA %s_smb-enum %s') % (port, os.path.join(OUTDIR, ip_address), ip_address)
        nmap_file = '%s_smb-enum.nmap' % os.path.join(OUTDIR, ip_address)
        if not os.path.exists(nmap_file):
            subprocess.check_output(SMBSCAN, shell=True)

    NBTSCAN = "./samrdump.py %s" % (ip_address)
    nbtresults = subprocess.check_output(NBTSCAN, shell=True)
    filename = os.path.join(OUTDIR, 'smbenum_%s' % ip_address)
    if ("Connection refused" not in nbtresults) and ("Connect error" not in nbtresults) and ("Connection reset" not in nbtresults):
        f = open(filename, 'w')
        print "[*] SAMRDUMP User accounts/domains found on " + ip_address
        lines = nbtresults.split("\n")
        for line in lines:
            if ("Found" in line) or (" . " in line):
                print "   [+] " + line
                f.write(line+'\n')
        f.close()
    return

def ftpEnum(ip_address, port, OUTDIR):
    if not args.ftp:
        return
    print "INFO: Detected ftp on " + ip_address + ":" + port
    print "INFO: Performing nmap FTP script scan for " + ip_address + ":" + port
    FTPSCAN = ('nmap -sV -Pn -vv -p %s '
               '--script=ftp-anon,ftp-bounce,ftp-libopie,ftp-proftpd-backdoor,ftp-vsftpd-backdoor,ftp-vuln-cve2010-4221 '
               '-oA %s_ftp.nmap %s') % (port, os.path.join(OUTDIR, ip_address), ip_address)
    results = subprocess.check_output(FTPSCAN, shell=True)

    print "INFO: Performing hydra ftp scan against " + ip_address 
    HYDRA = "hydra -L userlist -P passwordlist -f -o %s_ftphydra.txt -u %s -s %s ftp" % (os.path.join(OUTDIR, ip_address), ip_address, port)
    results = subprocess.check_output(HYDRA, shell=True)
    resultarr = results.split("\n")
    filename = os.path.join(OUTDIR, 'ftpenum_%s' % ip_address)
    f = open(filename, 'w')
    for result in resultarr:
        if "login:" in result:
            print "[*] Valid ftp credentials found: " + result
            f.write("[*] Valid ftp credentials found: " + result)
    f.close()
    return

def callScan():
    pass

def nmapScan(ip_address, OUTDIR):
    serv_dict = {}
    if not len(args.only):
        ip_address = ip_address.strip()
        print "INFO: Running general TCP/UDP nmap scans for " + ip_address
        serv_dict = {}
        TCPSCAN = ('nmap -vv -Pn -A -sC -sS -T 4 -p- -oA %s %s') % (os.path.join(OUTDIR, ip_address), ip_address)
        UDPSCAN = ('nmap -vv -Pn -A -sC -sU -T 4 --top-ports 200 -oA %sU %s') % (os.path.join(OUTDIR, ip_address), ip_address)
        tcp_nmap_file = '%s.nmap' % os.path.join(OUTDIR, ip_address)
        udp_nmap_file = '%sU.nmap' % os.path.join(OUTDIR, ip_address)
        if not os.path.exists(tcp_nmap_file):
            subprocess.check_output(TCPSCAN, shell=True)
        if not os.path.exists(udp_nmap_file):
            subprocess.check_output(UDPSCAN, shell=True)

        with open(tcp_nmap_file, 'r') as f:
            for line in f:
                ports = []
                line = line.strip()
                if ("tcp" in line) and ("open" in line) and not ("Discovered" in line):
                    while "  " in line: 
                        line = line.replace("  ", " ")
                    linesplit= line.split(" ")
                    service = linesplit[2] # grab the service name
                    port = line.split(" ")[0] # grab the port/proto
                    if service in serv_dict:
                        ports = serv_dict[service] # if the service is already in the dict, grab the port list

                    ports.append(port)
                    serv_dict[service] = ports # add service to the dictionary along with the associated port(2)
    else:
        port_dict = {
            'http': ['80'],
            'https': ['443'],
            'smtp': ['25'],
            'snmp': ['161', '162'],
            'domain': ['53'],
            'ftp': ['21'],
            'microsoft-ds': ['445'],
            'ms-sql': ['1433']
        }
        for i, serv in enumerate(args.only):
            services = []
            if serv == 'dns':
                services.append('domain')
            elif serv == 'dirb':
                if 'http' not in services:
                    services.append('http')
                if 'https' not in services:
                    services.append('https')
            elif serv == 'sql':
                services.append('ms-sql')
            elif serv == 'smb':
                services.append('microsoft-ds')
            else:
                services.append(serv)
            
            for s in services:
                serv_dict[s] = port_dict[s]


    # go through the service dictionary to call additional targeted enumeration functions 
    for serv in serv_dict:
        ports = serv_dict[serv]
        for port in ports:
            port = port.split('/')[0]
            if (serv == "http"):
                multProc(httpEnum, ip_address, port, OUTDIR)
            elif (serv == "ssl/http") or ("https" in serv):
                multProc(httpsEnum, ip_address, port, OUTDIR)
            elif "ssh" in serv:
                    multProc(sshEnum, ip_address, port, OUTDIR)
            elif "smtp" in serv:
                    multProc(smtpEnum, ip_address, port, OUTDIR)
            elif "snmp" in serv:
                    multProc(snmpEnum, ip_address, port, OUTDIR)
            elif "domain" in serv:
                    multProc(dnsEnum, ip_address, port, OUTDIR)
            elif "ftp" in serv:
                    multProc(ftpEnum, ip_address, port, OUTDIR)
            elif "microsoft-ds" in serv:
                    multProc(smbEnum, ip_address, port, OUTDIR)
            elif "ms-sql" in serv:
                    multProc(mssqlEnum, ip_address, port, OUTDIR)

    print "INFO: TCP/UDP Nmap scans completed for " + ip_address 
    return

def start_nmap_scan(ip, OUTDIR):
    p = multiprocessing.Process(target=nmapScan, args=(ip, OUTDIR))
    p.start()

def make_dir(path):
    if not os.path.exists(path):
        os.mkdir(path)

def main(dir_):
    print "############################################################"
    print "####                      RECON SCAN                    ####"
    print "####            A multi-process service scanner         ####"
    print "####        http, ftp, dns, ssh, snmp, smtp, ms-sql     ####"
    print "############################################################"
    # grab the discover scan results and start scanning up hosts
    if args.ip:
        OUTDIR = dir_
        if args.ip not in OUTDIR and not args.nodir:
            OUTDIR = os.path.join(dir_, args.ip)
            make_dir(OUTDIR)
        start_nmap_scan(args.ip, OUTDIR)
    else:
        for line in args.infile:
            ip = line.strip()
            OUTDIR = os.path.join(dir_, ip)
            make_dir(OUTDIR)
            start_nmap_scan(ip, OUTDIR)
        args.infile.close()

if __name__ == '__main__':
    parser = argparse.ArgumentParser(
        description='Enumerate a host or list of hosts',
        epilog='NOTE: Only input file OR IP address should be supplied'
    )
    parser.add_argument('ip', nargs='?', help='IP address of host to enumerate')
    parser.add_argument('-f', '--infile', type=file,
                        help='input file to read host to enumerate')
    parser.add_argument('-o', '--outdir', default='.',
                        help='output directory to store results')
    parser.add_argument('-N', '--nodir', action='store_true',
                        help='don\'t creat output directory')
    parser.add_argument('-S', '--ssh', action='store_true')
    parser.add_argument('-F', '--ftp', action='store_true')
    parser.add_argument('-O', '--only', nargs='+', help='List of checks to run in isolation',
                        default='')
    args = parser.parse_args()
    OUTDIR = os.path.abspath(args.outdir)
    if not os.path.exists(OUTDIR):
        print '''!!!!!!!!
                 Output directory %s does not exist' % OUTDIR
                 !!!!!!!!'''
    elif (not args.ip and not args.infile) or (args.ip and args.infile):
        parser.print_help()
    else:
        main(OUTDIR)
