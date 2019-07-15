#!/usr/local/oteemo/venv_nsx/bin/python2.7

# Copyright 2015 VMware Inc
# All Rights Reserved
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.

import optparse
import os
import sys

import requests
import itertools
import json
from requests.packages.urllib3.exceptions import InsecurePlatformWarning
from requests.packages.urllib3.exceptions import InsecureRequestWarning


class NSXClient(object):
    """Base NSX REST client"""

    def __init__(self, host, username, password, nsx_cert, key, ca_cert, cluster):
        self.host = host
        self.username = username
        self.password = password
        self.nsx_cert = nsx_cert
        self.key = key
        self.use_cert = bool(self.nsx_cert and self.key)
        self.ca_cert = ca_cert
        self.cluster = cluster
        self.resource_to_url = {
            'TransportZone': '/transport-zones',
            'LogicalRouter': '/logical-routers',
            'IpBlock': '/pools/ip-blocks',
            'IpPool': '/pools/ip-pools',
            'LogicalSwitch': '/logical-switches',
            'LogicalPort': '/logical-ports',
            'LogicalRouterPort': '/logical-router-ports',
            'VIF': '/fabric/vifs',
            'VM': '/fabric/virtual-machines',
            'LoadBalancerService': '/loadbalancer/services',
            'FirewallSection': '/firewall/sections',
            'NSGroup': '/ns-groups',
            'IPSets': '/ip-sets',
            'VirtualServer': '/loadbalancer/virtual-servers',
            'LoadBalancerRule': '/loadbalancer/rules',
            'LoadBalancerPool': '/loadbalancer/pools',
            'IPSubnets': '/pools/ip-subnets',
            'SwitchingProfile': '/switching-profiles',
            'Certificates': '/trust-management/certificates',
            'PersistenceProfile': '/loadbalancer/persistence-profiles'
        }
        self.header = {'X-Allow-Overwrite': 'true'}
        self.authenticate()

    def _get_top_tier_router(self):
        if self._t0_uuid or self._t1_uuid:
            router_response = self.get_logical_routers_by_uuid(
                self._t0_uuid or self._t1_uuid)
            if router_response.get('httpStatus') == 'NOT_FOUND':
                top_tier_routers = []
            else:
                top_tier_routers = [router_response]
        else:
            all_t0_routers = self.get_logical_routers(tier='TIER0')
            top_tier_routers = self.get_ncp_resources(all_t0_routers)
        if not top_tier_routers:
            raise Exception("Error: Missing cluster top-tier router")
        if len(top_tier_routers) > 1:
            raise Exception("Found %d top-tier routers " %
                            len(top_tier_routers))
        return top_tier_routers[0]

    def _resource_url(self, resource_type):
        return self.host + '/api/v1' + self.resource_to_url[resource_type]

    def make_get_call(self, full_url):
        if self.use_cert:
            return requests.get(full_url, cert=(self.nsx_cert, self.key),
                                headers=self.header,
                                verify=False).json()
        else:
            return requests.get(full_url, auth=(self.username, self.password),
                                headers=self.header,
                                verify=False).json()

    def make_post_call(self, full_url, body):
        if self.use_cert:
            return requests.post(full_url, cert=(self.nsx_cert, self.key),
                                headers=self.header,
                                verify=False, json=body)
        else:
            return requests.post(full_url, auth=(self.username, self.password),
                                headers=self.header,
                                verify=False, json=body) 
    
    def make_put_call(self, full_url, body): 
        if self.use_cert: 
            return requests.put(full_url, cert=(self.nsx_cert, self.key), 
                                headers=self.header, 
                                verify=False, json=body) 

        else: 
            return requests.put(full_url, auth=(self.username, self.password), 
                                headers=self.header, 
                                verify=False, json=body)

    def make_delete_call(self, full_url):
        if self.use_cert:
            return requests.delete(full_url, cert=(self.nsx_cert, self.key),
                                   headers=self.header,
                                   verify=False)
        else:
            return requests.delete(full_url, auth=(self.username, self.password),
                                   headers=self.header,
                                   verify=False)

    def get_resource_by_type(self, resource_type):
        resource_url = self._resource_url(resource_type)
        print(resource_url)
        res = []
        r_json = self.make_get_call(resource_url)
        while 'cursor' in r_json:
            res += r_json['results']
            url_with_paging = resource_url + '?' + 'cursor=' + r_json['cursor']
            r_json = self.make_get_call(url_with_paging)
        res += r_json['results']
        return res

    def get_resource_by_type_and_id(self, resource_type, uuid):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        print(resource_url)
        return self.make_get_call(resource_url)

    def get_resource_by_query_param(self, resource_type, query_param_type,
                                    query_param_id):
        resource_url = self._resource_url(resource_type)
        full_url = (resource_url + '/?' +
                    query_param_type + '=' + query_param_id)
        print(full_url)
        return self.make_get_call(full_url)

    def get_resource_by_param(self, resource_type, param_type, param_val):
        resource_url = self._resource_url(resource_type)
        full_url = resource_url + '?' + param_type + '=' + param_val
        print(full_url)
        return self.make_get_call(full_url)

    def get_secondary_resource(self, resource_type, uuid, secondary_resource):
        resource_url = self._resource_url(resource_type)
        print(resource_url)
        full_url = resource_url + '/' + uuid + '/' + secondary_resource
        print(full_url)
        return self.make_get_call(full_url)

    # used to update with API calls: POST url/resource/uuid?para=para_val
    def update_resource_by_type_and_id_and_param(self, resource_type, uuid,
                                                 param_type, param_val, body):
        resource_url = self._resource_url(resource_type) + '/' + uuid
        full_url = resource_url + '?' + param_type + '=' + param_val
        print(full_url)
        res = self.make_post_call(full_url, body)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)
        return res 

    # used to update with API calls: POST url/resource/uuid?para=para_val
    def update_resource_by_type_and_id(self, resource_type, uuid, body):
        full_url = self._resource_url(resource_type) + '/' + uuid
        print(full_url)
        res = self.make_put_call(full_url, body)
        if res.status_code != requests.codes.ok:
            raise Exception(res.text)
        return res

    def get_logical_ports(self):
        """
        Retrieve all logical ports on NSX backend
        """
        return self.get_resource_by_type('LogicalPort')

    def get_ncp_logical_ports(self):
        """
        Retrieve all logical ports created by NCP
        """
        lports = self.get_ncp_resources(
            self.get_logical_ports())
        return lports

    def is_node_lsp(self, lport):
        # Node LSP can be updated by NCP to be parent VIF type, but could also
        # be a normal VIF without context before NCP updates it
        if lport.get('attachment'):
            if (lport['attachment']['attachment_type'] == 'VIF' and
                (not lport['attachment']['context'] or
                 lport['attachment']['context']['vif_type'] == 'PARENT')):
                return True
        return False

    def _is_ncp_resource(self, tags):
        return any(tag.get('scope') == 'ncp/cluster' and
                   tag.get('tag') == self._cluster for tag in tags)

    def _is_ncp_ha_resource(self, tags):
        return any(tag.get('scope') == 'ncp/ha' and
                   tag.get('tag') == 'true' for tag in tags)

    def _is_ncp_shared_resource(self, tags):
        return any(tag.get('scope') == 'ncp/shared_resource' and
                   tag.get('tag') == 'true' for tag in tags)

    def get_ncp_resources(self, resources):
        """
        Get all logical resources created by NCP
        """
        ncp_resources = [r for r in resources if 'tags' in r
                         if self._is_ncp_resource(r['tags'])]
        return ncp_resources

    def get_ncp_shared_resources(self, resources):
        """
        Get all logical resources with ncp/cluster tag
        """
        ncp_shared_resources = [r for r in resources if 'tags' in r
                                if self._is_ncp_shared_resource(r['tags'])]
        return ncp_shared_resources

    def get_logical_switches(self):
        """
        Retrieve all logical switches on NSX backend
        """
        return self.get_resource_by_type('LogicalSwitch')

    def get_ncp_logical_switches(self):
        """
        Retrieve all logical switches created from NCP
        """
        lswitches = self.get_ncp_resources(
            self.get_logical_switches())

        return lswitches

    def get_lswitch_ports(self, ls_id):
        """
        Return all the logical ports that belong to this lswitch
        """
        lports = self.get_logical_ports()
        return [p for p in lports if p['logical_switch_id'] == ls_id]
              
    def get_firewall_sections(self):
        """
        Retrieve all firewall sections
        """
        return self.get_resource_by_type('FirewallSection')

    def get_ncp_firewall_sections(self):
        """
        Retrieve all firewall sections created from NCP
        """
        fw_sections = self.get_ncp_resources(
            self.get_firewall_sections())
        return fw_sections

    def get_ns_groups(self):
        return self.get_resource_by_type('NSGroup')

    def get_ns_ncp_groups(self):
        """
        Retrieve all NSGroups on NSX backend
        """
        ns_groups = self.get_ncp_resources(self.get_ns_groups())
        return ns_groups

    def _escape_data(self, data):
        # ElasticSearch query_string requires slashes and dashes to
        # be escaped. We assume no other reserved character will be
        # used in tag scopes or values
        return data.replace('/', '\\/').replace('-', '\\-')

    def get_ip_sets(self):
        return self.get_resource_by_type('IPSets')

    def get_ncp_ip_sets(self):
        ip_sets = self.get_ncp_resources(self.get_ip_sets())
        return ip_sets

    def get_logical_routers(self, tier=None):
        """
        Retrieve all the logical routers based on router type. If tier
        is None, it will return all logical routers.
        """
        lrouters = self.get_resource_by_type('LogicalRouter')
        if tier:
            lrouters = [router for router in lrouters
                        if router['router_type'] == tier]
        return lrouters

    def get_logical_routers_by_uuid(self, uuid):
        """
        Retrieve the logical router with specified UUID.
        """
        return self.get_resource_by_type_and_id('LogicalRouter', uuid)

    def get_ncp_logical_routers(self):
        """
        Retrieve all logical routers created from Neutron NSXv3 plugin
        """
        lrouters = self.get_logical_routers()
        return self.get_ncp_resources(lrouters)

    def get_logical_router_ports(self, lrouter):
        """
        Get all logical ports attached to lrouter
        """
        return self.get_resource_by_param('LogicalRouterPort',
                                          'logical_router_id',
                                          lrouter['id'])['results']

    def get_ncp_logical_router_ports(self, lrouter):
        """
        Retrieve all logical router ports created from Neutron NSXv3 plugin
        """
        lports = self.get_logical_router_ports(lrouter)
        return self.get_ncp_resources(lports)

    def get_tier1_link_port(self, t1_uuid):
        logical_router_ports = self.get_resource_by_param(
            'LogicalRouterPort', 'logical_router_id', t1_uuid)['results']
        for port in logical_router_ports:
            if port['resource_type'] == 'LogicalRouterLinkPortOnTIER1':
                return port

    def get_ip_pools(self):
        """
        Retrieve all ip_pools on NSX backend
        """
        return self.get_resource_by_type('IpPool')

    def get_ncp_get_ip_pools(self):
        """
        Retrieve all logical switches created from NCP
        """
        ip_pools = self.get_ncp_resources(
            self.get_ip_pools())

        return ip_pools

    def get_ncp_lb_services(self):
        lb_services = self.get_lb_services()
        return self.get_ncp_resources(lb_services)

    def get_lb_services(self):
        return self.get_resource_by_type('LoadBalancerService')

    def get_ncp_lb_virtual_servers(self):
        lb_virtual_servers = self.get_virtual_servers()
        return self.get_ncp_resources(lb_virtual_servers)

    def get_virtual_servers(self):
        return self.get_resource_by_type('VirtualServer')

    def get_ncp_lb_rules(self):
        lb_rules = self.get_lb_rules()
        return self.get_ncp_resources(lb_rules)

    def get_lb_rules(self):
        return self.get_resource_by_type('LoadBalancerRule')

    def get_ncp_lb_pools(self):
        lb_pools = self.get_lb_pools()
        return self.get_ncp_resources(lb_pools)

    def get_lb_pools(self):
        return self.get_resource_by_type('LoadBalancerPool')

    def get_ncp_persistence_profiles(self):
        return self.get_ncp_resources(
            self.get_resource_by_type('PersistenceProfile'))

    def get_ip_blocks(self):
        return self.get_resource_by_type('IpBlock')

    def get_ncp_ip_blocks(self):
        ip_blocks = self.get_ip_blocks()
        return self.get_ncp_resources(ip_blocks)

    def get_switching_profiles(self):
        sw_profiles = self.get_resource_by_type('SwitchingProfile')
        return sw_profiles

    def get_ncp_switching_profiles(self):
        sw_profiles = self.get_switching_profiles()
        return self.get_ncp_resources(sw_profiles)

    def get_l7_resource_certs(self):
        return self.get_resource_by_type('Certificates')

    def get_ncp_l7_resource_certs(self):
        l7_resource_certs = self.get_l7_resource_certs()
        return self.get_ncp_resources(l7_resource_certs)

    def get_logical_ports_for_second_vnic(self): 
        mgmt_logical_switch_name = 'KUBE-VIF-10.181.238.0_25'       # Name of the second vNic 
        mgmt_logical_switch_id = '9d013cef-506c-4148-9c47-78c06458e1d6'     # ID of the second vNic
        return self.get_lswitch_ports(mgmt_logical_switch_id)   # Returns a list of dictionaries that correspond to each port

    def generate_node_names(self): 
        '''# Dynamically generate the VM names by using cluster name 
             (except dev-ecos and mgmtnp-ecos)'''
        prefixes = ['dev-ecos', 'mgmtnp-ecos', 'sdbx-ecos'] 
        cluster = self.cluster
        types_of_nodes = ['-c', '-i', '-m']
 
        nodes = []
        if cluster not in prefixes: 
            for node in types_of_nodes: 
                if node == 'c': 
                    for n in range(1, 10): 
                        name = cluster + node + ("%03d" % n)
                        nodes.append(unicode(name, 'utf-8'))
                else: 
                    for i in range(1, 4): 
                        name = cluster + node + ("%03d" % i)
                        nodes.append(unicode(name, 'utf-8')) 
        
        elif cluster in prefixes: 
            if cluster == 'dev-ecos': 
                nodes = [
                    u'dlv-ecos-c001', 
                    u'dlv-ecos-c002', 
                    u'dlv-ecos-c003', 
                    u'dlv-ecos-c004', 
                    u'dlv-ecos-c005', 
                    u'dlv-ecos-c006', 
                    u'dlv-ecos-c007', 
                    u'dlv-ecos-c008', 
                    u'dlv-ecos-c009', 
                    u'dlv-ecos-c010', 
                    u'dlv-ecos-i001', 
                    u'dlv-ecos-i002', 
                    u'dlv-ecos-i003', 
                    u'dlv-ecos-m001', 
                    u'dlv-ecos-m002', 
                    u'dlv-ecos-m003', 
                    ] 

            elif cluster == 'mgmtnp-ecos':
                nodes = [
                    u'dlv-ecos-c011', 
                    u'dlv-ecos-c012', 
                    u'dlv-ecos-c013', 
                    u'dlv-ecos-c014', 
                    u'dlv-ecos-c026', 
                    u'dlv-ecos-c027', 
                    u'dlv-ecos-c028', 
                    u'dlv-ecos-c029', 
                    u'dlv-ecos-c030', 
                    u'dlv-ecos-c031', 
                    u'dlv-ecos-i004', 
                    u'dlv-ecos-i005', 
                    u'dlv-ecos-i006', 
                    u'dlv-ecos-m005', 
                    u'dlv-ecos-m006', 
                    u'dlv-ecos-m007', 
                    ]

            elif cluster == 'sdbx-ecos':
                nodes = [
                    u'dlv-ecos-c032', 
                    u'dlv-ecos-c033', 
                    u'dlv-ecos-c034', 
                    u'dlv-ecos-c035', 
                    u'dlv-ecos-c036', 
                    u'dlv-ecos-c037', 
                    u'dlv-ecos-c038', 
                    u'dlv-ecos-c039', 
                    u'dlv-ecos-c040', 
                    u'dlv-ecos-c041', 
                    u'dlv-ecos-i007', 
                    u'dlv-ecos-i008', 
                    u'dlv-ecos-i009', 
                    u'dlv-ecos-m004', 
                    u'dlv-ecos-m008', 
                    u'dlv-ecos-m009', 
                    ]
        
        return nodes 

    def tag_logical_ports_of_second_vnic(self, lports, nodes): 
        '''Tags the logical ports associated with the second vNic.'''
        lports = lports     # A list of dictionaries that correspond to each logical port associated w/ 2nd vNic
        cluster = self.cluster   # Cluster name passed in w/ optparse
        display_names = []  # Have list of display names for the VMs we want to tag 
        filter_lports = []   # Need to filter all of the ports down to the ports that we need to tag

        # Filter ports for tagging and get display names
        for dict_of_port in lports:     
            display_name = dict_of_port['display_name'] 
            name = display_name.split('/', 1)[0]    # Gets the vm name from the display name
            if name in nodes: 
                display_names.append(name)  
                filter_lports.append(dict_of_port)  # Only get ports for the VMs we want to tag

        # Tag Nics
        for dict_of_port, display_name in zip(filter_lports, display_names):    # Iterate through both the port and the VMs name
            d1 = {} # Empty dict to hold the scope/tag for cluster 
            d2 = {} # Empty dict to hold the scope/tag for node name 
            dict_of_port.setdefault('tags', [])    # If tags key not in ports, create it on the fly w/ a value of an empty list

            # Assign first set of tags
            d1['scope'] = 'ncp/cluster' 
            d1['tag'] = cluster 

            dict_of_port['tags'].append(d1) 

            # Assign second set of tags
            d2['scope'] = 'ncp/node_name' 
            d2['tag'] = str(display_name) 

            dict_of_port['tags'].append(d2)

        # Below Algo may be useful in the future
        """ for dict_of_port, display_name in zip(filter_lports, display_names):     # Skip the first dictionary b/c its the logical port of the 2nd vNic 
            for key in dict_of_port.keys():
                if key == 'tags':
                    for i, dict_of_tags in enumerate(dict_of_port['tags'], 0): 
                        if display_name in nodes: 
                            if i == 0: 
                                u_cluster_tag = unicode('ncp/cluster', 'utf-8')
                                u_cluster_name = unicode(cluster, 'utf-8')
                                dict_of_tags['scope'] = u_cluster_tag 
                                dict_of_tags['tag'] = u_cluster_name

                            elif i == 1:
                                u_node_tag = unicode('ncp/node_name', 'utf-8')
                                u_node_name = display_name
                                dict_of_tags['scope'] = u_node_tag
                                dict_of_tags['tag'] = u_node_name   """
                            
        return(filter_lports) 

    def update_nsx_vnic_tags(self, tagged_ports): 
        '''Make update put call.''' 
        tagged_ports = tagged_ports     # Gets tagged ports from output of tag function
        uuids = []  # Required to make put call
        tags = []   # What we are updating 
        admin_states = []   # Required to make put call 
        logical_switch_ids = []     # Required to make put call 
        _revisions = []     # Required to make put call 
        attachments = []    # Required to make put call
        
        # Get each individual value from the tagged ports and put in dedicated list
        for dict_of_port in tagged_ports: 
            uuid = dict_of_port['id']
            uuids.append(str(uuid))     # Shouldn't matter if type str or unicode
            admin_state = dict_of_port['admin_state']
            admin_states.append(admin_state) 
            logical_switch_id = dict_of_port['logical_switch_id']
            logical_switch_ids.append(logical_switch_id)
            _revision = dict_of_port['_revision']
            _revisions.append(_revision)
            attachment = dict_of_port['attachment']
            attachments.append(attachment)
            tag = dict_of_port['tags']
            tags.append(tag)

        for uuid, tag, admin_state, logical_switch_id, _revision, attachment in zip(uuids, tags, admin_states, logical_switch_ids, _revisions, attachments): 
            m = json.dumps({'logical_switch_id': logical_switch_id, 'admin_state': admin_state, 'tags': tag, '_revision': _revision, 'attachment': attachment})
            json_tag = json.loads(m)
            self.update_resource_by_type_and_id(resource_type='LogicalPort', uuid=uuid, body=json_tag)

    def authenticate(self):
        # make a get call to make sure response is not forbidden
        full_url = self.host
        if self.use_cert:
            response = requests.get(full_url, cert=(self.nsx_cert, self.key),
                                headers=self.header,
                                verify=False)
        else:
            response = requests.get(full_url,
                                    auth=(self.username, self.password),
                                    headers=self.header,
                                    verify=False)
        if response.status_code == requests.codes.forbidden:
            print("ERROR: Authentication failed! "
                  "Please check your credentials.")
            exit(1)

   
def validate_options(options):
    if not options.mgr_ip:
        print("Required arguments missing. Run '<script_name> -h' for usage")
        sys.exit(1)
    if (not options.password and not options.username and
        not options.nsx_cert and not options.key):
        print("Required authentication parameter missing. "
              "Run '<script_name> -h' for usage")
        sys.exit(1) 
    if not options.cluster:
        print("Need to provide cluster name in order to tag nic." 
              "Run '<script_name> -h' for usage")
        sys.exit(1)

if __name__ == "__main__":

    parser = optparse.OptionParser()
    parser.add_option("--mgr-ip", dest="mgr_ip", help="NSX Manager IP address")
    parser.add_option("-u", "--username", default="", dest="username",
                      help="NSX Manager username, ignored if nsx-cert is set")
    parser.add_option("-p", "--password", default="",
                      dest="password",
                      help="NSX Manager password, ignored if nsx-cert is set")
    parser.add_option("-n", "--nsx-cert", default="", dest="nsx_cert",
                      help="NSX certificate path")
    parser.add_option("-k", "--key", default="", dest="key",
                      help="NSX client private key path")
    parser.add_option("-t", "--ca-cert", default="", dest="ca_cert",
                      help="NSX ca_certificate")
    parser.add_option("--no-warning", action="store_true", dest="no_warning",
                      help="Disable urllib's insecure request warning") 
    parser.add_option("-c", "--cluster", dest="cluster",
                      help="Cluster name to tag to scope: ncp/cluster")
    (options, args) = parser.parse_args()

    if options.no_warning:
        requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
        requests.packages.urllib3.disable_warnings(InsecurePlatformWarning)

    validate_options(options)
    # Get NSX REST client
    nsx_client = NSXClient(host=options.mgr_ip,
                           username=options.username,
                           password=options.password,
                           nsx_cert=options.nsx_cert,
                           key=options.key,
                           ca_cert=options.ca_cert, 
                           cluster=options.cluster) 

    json_ports = nsx_client.get_logical_ports_for_second_vnic()     # Get all the ports associated with the second vNic
    node_names = nsx_client.generate_node_names()   # Get the node names for the VMs that we want to tag
    tagged_ports = nsx_client.tag_logical_ports_of_second_vnic(json_ports, node_names)  # Get the tagged ports
    nsx_client.update_nsx_vnic_tags(tagged_ports)   # Update the ports