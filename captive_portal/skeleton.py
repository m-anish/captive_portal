#!/usr/bin/env python
# -*- coding: utf-8 -*-
"""
This is a skeleton file that can serve as a starting point for a Python
console script. To run this script uncomment the following line in the
entry_points section in setup.py:

    [console_scripts]
    fibonacci = captive_portal.skeleton:run

Then run `python setup.py install` which will install the command `fibonacci`
inside your current environment.
Besides console scripts, the header (i.e. until _logger...) of this file can
also be used as template for Python modules.

Note: This skeleton file can be safely removed if not needed!
"""
from __future__ import division, print_function, absolute_import

import argparse
import sys
import logging
import subprocess
import BaseHTTPServer
import cgi

from captive_portal import __version__

# These variables are used as settings
PORT       = 9090         # the port in which the captive portal web server listens 
IFACE      = "br0"      # the interface that captive portal protects
IP_ADDRESS = "172.18.96.1" # the ip address of the captive portal (it can be the IP of IFACE) 
USERNAME   = "Admin"
PASSWORD   = "g0adm1n"

__author__ = "Anish Mangal"
__copyright__ = "Anish Mangal"
__license__ = "gpl3"

_logger = logging.getLogger(__name__)


'''
'''
class CaptivePortal(BaseHTTPServer.BaseHTTPRequestHandler):
    """This it the http server used by the the captive portal
    
    """
   

    """Initialize the captive portal html pages
    
        Args:
          port (int): The port on which the portal is active
          ip_address (istr): The ip address on which the portal is active
          username: Authentication username
          password: Authentication password
    """
    def __init__(self, port=PORT, ip_address=IP_ADDRESS, username=USERNAME, password=PASSWORD): 
        #this is the index of the captive portal
        #it simply redirects the user to the to login page
        html_redirect = """
        <html>
        <head>
            <meta http-equiv="refresh" content="0; url=http://%s:%s/login" />
        </head>
        <body>
            <b>Redirecting to login page</b>
        </body>
        </html>
        """%(ip_address, port)
        
        #the login page
        html_login = """
        <html>
        <body>
            <b>Login Form</b>
            <form method="POST" action="do_login">
            Username: <input type="text" name="username"><br>
            Password: <input type="password" name="password"><br>
            <input type="submit" value="Submit">
            </form>
        </body>
        </html>
        """
    
    '''
    if the user requests the login page show it, else
    use the redirect page
    '''
    def do_GET(self):
        path = self.path
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        if path == "/login":
            self.wfile.write(self.html_login)
        else:
            self.wfile.write(self.html_redirect)
    '''
    this is called when the user submits the login form
    '''
    def do_POST(self):
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        form = cgi.FieldStorage(
            fp=self.rfile, 
            headers=self.headers,
            environ={'REQUEST_METHOD':'POST',
                     'CONTENT_TYPE':self.headers['Content-Type'],
                     })
        submitted_username = form.getvalue("username")
        submitted_password = form.getvalue("password")
        #dummy security check
        if submitted_username == username and submitted_password == password:
            #authorized user
            remote_IP = self.client_address[0]
            print("New authorization from %s" % remote_IP)
            print("Updating IP tables")
            subprocess.call(["iptables","-t", "nat", "-I", "PREROUTING","1", "-s", remote_IP, "-j" ,"ACCEPT"])
            subprocess.call(["iptables", "-I", "FORWARD", "-s", remote_IP, "-j" ,"ACCEPT"])
            self.wfile.write("You are now authorized. Navigate to any URL")
        else:
            #show the login form
            self.wfile.write(self.html_login)

def setup_initial_iptables(port=PORT, iface=IFACE, ip_address=IP_ADDRESS):
    print("*********************************************")
    print("* Note, if there are already iptables rules *")
    print("* this script may not work. Flush iptables  *")
    print("* at your own riks using iptables -F        *")
    print("*********************************************")
    print("Updating iptables")
    print(".. Allow TCP DNS")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--dport", "53", "-j" ,"ACCEPT"])
    print(".. Allow UDP DNS")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", iface, "-p", "udp", "--dport", "53", "-j" ,"ACCEPT"])
    print(".. Allow traffic to captive portal")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", iface, "-p", "tcp", "--dport", str(port),"-d", ip_address, "-j" ,"ACCEPT"])
    print(".. Block all other traffic")
    subprocess.call(["iptables", "-A", "FORWARD", "-i", iface, "-j" ,"DROP"])
    print("Redirecting HTTP traffic to captive portal")
    subprocess.call(["iptables", "-t", "nat", "-A", "PREROUTING", "-i", iface, "-p", "tcp", "--dport", "80", "-j" ,"DNAT", "--to-destination", ip_address+":"+str(port)])

def start_captive_server(port=PORT, iface=IFACE, ip_address=IP_ADDRESS, username=USERNAME, password=PASSWORD):
    print "Starting web server"
    httpd = BaseHTTPServer.HTTPServer(('', port), CaptivePortal)
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        pass
    httpd.server_close()

def parse_args(args):
    """Parse command line parameters

    Args:
      args ([str]): command line parameters as list of strings

    Returns:
      :obj:`argparse.Namespace`: command line parameters namespace
    """
    parser = argparse.ArgumentParser(
        description="Just a Fibonnaci demonstration")
    parser.add_argument(
        '--version',
        action='version',
        version='captive_portal {ver}'.format(ver=__version__))
    parser.add_argument(
        dest="n",
        help="n-th Fibonacci number",
        type=int,
        metavar="INT")
    parser.add_argument(
        '-v',
        '--verbose',
        dest="loglevel",
        help="set loglevel to INFO",
        action='store_const',
        const=logging.INFO)
    parser.add_argument(
        '-vv',
        '--very-verbose',
        dest="loglevel",
        help="set loglevel to DEBUG",
        action='store_const',
        const=logging.DEBUG)
    return parser.parse_args(args)


def setup_logging(loglevel):
    """Setup basic logging

    Args:
      loglevel (int): minimum loglevel for emitting messages
    """
    logformat = "[%(asctime)s] %(levelname)s:%(name)s:%(message)s"
    logging.basicConfig(level=loglevel, stream=sys.stdout,
                        format=logformat, datefmt="%Y-%m-%d %H:%M:%S")


def main(args):
    """Main entry point allowing external calls

    Args:
      args ([str]): command line parameter list
    """
    args = parse_args(args)
    setup_logging(args.loglevel)
    _logger.debug("Starting crazy calculations...")
    setup_initial_iptables()
    start_captive_server()
    #print("The {}-th Fibonacci number is {}".format(args.n, fib(args.n)))
    _logger.info("Script ends here")


def run():
    """Entry point for console_scripts
    """
    main(sys.argv[1:])


if __name__ == "__main__":
    run()
