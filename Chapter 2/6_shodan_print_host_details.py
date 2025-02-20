# shodan_print_host_details.py

"""
Description:
    Use Shodan to get all the public information about a target system.

Author:
    Nishant Krishna

Created:
    15 May, 2022
"""
import os

from dotenv import load_dotenv
from shodan import Shodan
import json

# Завантажуємо змінні середовища з .env файлу
load_dotenv()

# Отримуємо API-ключ із середовища
api_key = os.getenv('SHODAN_API_KEY')

if api_key is None:
    raise ValueError("Shodan API key is missing in environment variables.")
api = Shodan(api_key)


class ShodanHostDetails:
    def print_host_details(self, ip_address):
        """""
        Print details about the IP address

        Args:
            ip_address (String): IP address to scan
        """
        ipinfo = api.host(ip_address)
        print(json.dumps(ipinfo, indent=4))


if __name__ == "__main__":
    shodan_info = ShodanHostDetails()
    shodan_info.print_host_details('<<IP Address>>')
