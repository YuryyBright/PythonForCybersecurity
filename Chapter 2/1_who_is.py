# whois_info.py

"""
Description:
    Get "whois" details for a host.

Author:
    Nishant Krishna

Created:
    05 May, 2022

    Using “dig” to get information about an IP
        address or domain name
        dig is a command-line tool that can query the Domain Name System (DNS)records for a domain.
        Note: Dig command is part of Linux and macOS. However, in Windows, you
        will need to use a different way, for example, Windows System for Linux (WSL)
        or another utility. This program can be run on Linux and Mac only. Running it
        on Windows will result in an error. If you want to run this program in Windows,
        you can do so inside Windows Subsystem for Linux (WSL) discussed in Chapter
"""

import whois as ws


class WhoisInfo:
    def print_whois_info(self, host):
        """
            host: Host that you want the whois details for.
        """

        whois_info = ws.whois(host)
        print(whois_info)


if __name__ == "__main__":
    whois_info = WhoisInfo()
    whois_info.print_whois_info("www.president.gospmr.org")
