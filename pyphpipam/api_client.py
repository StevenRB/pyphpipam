import requests
import json
import warnings
import getpass

# https://github.com/StevenRB/pyphpipam

logger = logging.getLogger()


class phpipamcfg:

    username = input("Username: ")
    password = getpass("Password: ")
    url_base = input("URL Base: ")

    url = f"https://{url_base}/api/testAppId/"
    cert = False
    ssl_warn = False


# Disables the SSL warning alert
if phpipamcfg.ssl_warn is False:
    warnings.filterwarnings("ignore")


class IpAdmin(object):
    def __init__(self):
        self.base_url = phpipamcfg.url
        self.cert_path = phpipamcfg.cert
        self.__username = phpipamcfg.username
        self.__password = phpipamcfg.password
        self.__token = self.login()
        self.headers = {"token": self.__token, "Content-type": "application/json"}

    # The token that we're pulling here is an authorization code that gets put in the header of every request
    def login(self):
        call = requests.post(
            self.base_url + "user/", auth=(self.__username, self.__password), verify=self.cert_path
        )
        if call.status_code != 200:
            return "Login Error"
        else:
            return json.loads(call.text)["data"]["token"]

    # Retrieves a subnet's ID. Arg is a network, expressed as a CIDR string
    def get_subnet_id(self, subnet, simple=False):
        call = requests.get(
            self.base_url + "subnets/cidr/{}/".format(subnet),
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Picks the next subnet in the parent. Mask is bit length like with CIDR (int)
    def get_next_subnet(self, parent_id, mask, simple=False):
        call = requests.get(
            self.base_url + "subnets/{}/first_subnet/{}/".format(parent_id, mask),
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Retrieves all addresses in a subnet. Returns a list of dictionaries
    def get_all_addresses(self, subnet_id, simple=False):
        call = requests.get(
            self.base_url + "subnets/{}/addresses/".format(subnet_id),
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Creates the next subnet in the parent. Mask is bit length like with CIDR (int)
    # Returns a dictionary with code, message, data (CIDR), id, success, and time
    def create_next_subnet(self, parent_id, mask, desc, simple=False):
        data = {"description": "{}".format(desc)}
        call = requests.post(
            self.base_url + "subnets/{}/first_subnet/{}/".format(parent_id, mask),
            params=data,
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Retrieves an address's ID. Arg is a IP
    def get_address_id(self, ip_add, simple=False):
        call = requests.get(
            self.base_url + "addresses/search/{}/".format(ip_add),
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Creates the next IP address in the parent subnet.
    def create_next_ip(self, parent_id, desc, simple=False):
        data = {"description": "{}".format(desc)}
        call = requests.post(
            self.base_url + "addresses/first_free/{}/".format(parent_id),
            params=data,
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Creates specific subnet in the parent. Mask is bit length like with CIDR (int)
    def create_subnet(self, parent_id, network, mask, desc, simple=False):
        data = {
            "masterSubnetId": "{}".format(parent_id),
            "description": "{}".format(desc),
            "subnet": "{}".format(network),
            "mask": "{}".format(mask),
            "sectionId": 5,
        }
        call = requests.post(
            self.base_url + "subnets/", params=data, headers=self.headers, verify=self.cert_path
        )
        return simple_return(call, simple)

    # Creates specific IP in the parent subnet
    def create_address(self, parent_id, ip, desc, simple=False):
        data = {
            "subnetId": "{}".format(parent_id),
            "description": "{}".format(desc),
            "ip": "{}".format(ip),
            "note": "Created via API",
        }
        call = requests.post(
            self.base_url + "addresses/", params=data, headers=self.headers, verify=self.cert_path
        )
        return simple_return(call, simple)

    # Updates the description on a specific IP
    def update_address(self, address_id, desc, simple=False):
        data = {"description": "{}".format(desc)}
        call = requests.patch(
            self.base_url + "addresses/{}/".format(address_id),
            params=data,
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Updates the description on a specific subnet
    def update_subnet(self, subnet_id, desc, simple=False):
        data = {"description": "{}".format(desc)}
        call = requests.patch(
            self.base_url + "subnets/{}/".format(subnet_id),
            params=data,
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

        # Creates an L2 Domain using a name

    def create_domain(self, name, simple=False):
        data = {"name": "{}".format(name)}
        call = requests.post(
            self.base_url + "l2domains/", params=data, headers=self.headers, verify=self.cert_path
        )
        return simple_return(call, simple)

    # Requests all L2Domains
    def getdomain(self):
        call = requests.get(
            self.base_url + "l2domains/", headers=self.headers, verify=self.cert_path
        )
        simple = False
        return simple_return(call, simple)

    # Creates a vlan. Default domain is #1
    def create_vlan(self, name, number, domain=1, simple=False):
        data = {
            "name": "{}".format(name),
            "domainId": "{}".format(domain),
            "number": "{}".format(number),
        }
        call = requests.post(
            self.base_url + "vlan/", params=data, headers=self.headers, verify=self.cert_path
        )
        return simple_return(call, simple)

    # Creates location using a name and a street address (both string)
    def create_location(self, name, address, simple=False):
        data = {"name": "{}".format(name), "address": "{}".format(address)}
        call = requests.post(
            self.base_url + "tools/locations/",
            headers=self.headers,
            params=data,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # Deletes a subnet referenced by subnet ID. Will not delete child subnets
    # !!! DOES NOT ASK FOR VERIFICATION !!!
    def delete_subnet(self, subnet_id):
        call = requests.delete(
            self.base_url + "subnets/{}/".format(subnet_id),
            headers=self.headers,
            verify=self.cert_path,
        )
        info = json.loads(call.text)
        return info

    def get_address_info(self, address_id, simple=False):
        call = requests.get(
            self.base_url + "addresses/{}/".format(address_id),
            headers=self.headers,
            verify=self.cert_path,
        )
        return simple_return(call, simple)

    # ############ DELETIONS ##############

    # Deletes all addresses in a subnet
    # !!! DOES NOT ASK FOR VERIFICATION !!!
    def delete_subnet_ips(self, subnet_id):
        call = requests.delete(
            self.base_url + "subnets/{}/truncate".format(subnet_id),
            headers=self.headers,
            verify=self.cert_path,
        )
        info = json.loads(call.text)
        return info

    # Delete a specific address
    # !!! DOES NOT ASK FOR VERIFICATION !!!
    def delete_address(self, address_id):
        call = requests.delete(
            self.base_url + "addresses/{}/".format(address_id),
            headers=self.headers,
            verify=self.cert_path,
        )
        info = json.loads(call.text)
        return info

    # COMBOS   More than one function smashed together for extra usability

    # Takes in a CIDR network and creates the next subnet of mask X
    def create_next_in_net(self, subnet, mask, desc, simple=False):
        parent_id = self.get_subnet_id(subnet, simple)
        info = self.create_next_subnet(parent_id, mask, desc, simple)
        return info

    # Takes in a CIDR network and creates the next address in it
    def create_next_add_in_net(self, subnet, desc, simple=False):
        parent_id = self.get_subnet_id(subnet, simple)
        info = self.create_next_ip(parent_id, desc, simple)
        return info

    # Takes in a CIDR network and creates an address in it
    def create_add_in_net(self, subnet, ip, desc, simple=False):
        parent_id = self.get_subnet_id(subnet, simple)
        info = self.create_address(parent_id, ip, desc, simple)
        return info

    # Creates specific subnet. Parent is CIDR, network is dotted decimal, mask is bitmask int
    def create_net_in_net(self, parent_sub, network, mask, desc, simple=False):
        parent_id = self.get_subnet_id(parent_sub, simple)
        info = self.create_subnet(parent_id, network, mask, desc, simple)
        return info


class PhpIpAdminError(Exception):
    def __init__(self, *args):
        error_str = ""
        for arg in args:
            error_str += " | {}".format(arg)
        Exception.__init__(self, "PhpIpAdminError{}".format(error_str))


def simple_return(call, simple):
    call_dict = json.loads(call.text)
    if "data" in call_dict:
        return call_dict
    else:
        if simple is True:
            return False
        else:
            return call_dict["message"]


if __name__ == "__main__":

    print("Thanks for using Steve's awesome IP info tool")
    ip = input("Please input your IP: ")

    session = IpAdmin()
    try:
        ip_id = session.get_address_id(ip)
    except Exception as e:
        print("There was a general failure: {}".format(e))
        exit()
    if ip_id:
        for k, v in ip_id["data"][0].items():
            print("{}  -- {}".format(k, v))
    else:
        print("Sorry but no information is available")
