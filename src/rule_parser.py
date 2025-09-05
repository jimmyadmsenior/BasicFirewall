"""
RuleParser module - handles firewall rule parsing and evaluation
"""

import logging
import ipaddress
import re

class Rule:
    """
    Represents a single firewall rule
    """
    
    def __init__(self, rule_dict):
        """
        Initialize a rule from a dictionary
        
        Args:
            rule_dict (dict): Dictionary containing rule parameters
        """
        self.name = rule_dict.get('name', 'Unnamed Rule')
        self.action = rule_dict.get('action', 'allow').lower()
        self.priority = rule_dict.get('priority', 100)
        
        # Network conditions
        self.src_ip = rule_dict.get('src_ip')
        self.dst_ip = rule_dict.get('dst_ip')
        self.src_port = rule_dict.get('src_port')
        self.dst_port = rule_dict.get('dst_port')
        self.protocol = rule_dict.get('protocol')
        
        # Compile IP network objects if specified
        self.src_network = None
        self.dst_network = None
        
        if self.src_ip:
            try:
                self.src_network = ipaddress.ip_network(self.src_ip, strict=False)
            except ValueError:
                logging.warning(f"Invalid source IP in rule {self.name}: {self.src_ip}")
                
        if self.dst_ip:
            try:
                self.dst_network = ipaddress.ip_network(self.dst_ip, strict=False)
            except ValueError:
                logging.warning(f"Invalid destination IP in rule {self.name}: {self.dst_ip}")
    
    def match(self, packet_info):
        """
        Check if a packet matches this rule
        
        Args:
            packet_info (dict): Packet information dictionary
            
        Returns:
            bool: True if packet matches rule, False otherwise
        """
        # Check source IP
        if self.src_network and 'src_ip' in packet_info:
            try:
                src_ip = ipaddress.ip_address(packet_info['src_ip'])
                if src_ip not in self.src_network:
                    return False
            except ValueError:
                return False
        
        # Check destination IP
        if self.dst_network and 'dst_ip' in packet_info:
            try:
                dst_ip = ipaddress.ip_address(packet_info['dst_ip'])
                if dst_ip not in self.dst_network:
                    return False
            except ValueError:
                return False
        
        # Check source port
        if self.src_port is not None and 'src_port' in packet_info:
            if not self._port_match(self.src_port, packet_info['src_port']):
                return False
        
        # Check destination port
        if self.dst_port is not None and 'dst_port' in packet_info:
            if not self._port_match(self.dst_port, packet_info['dst_port']):
                return False
        
        # Check protocol
        if self.protocol and 'proto' in packet_info:
            proto_num = packet_info['proto']
            
            # Handle protocol by name or number
            if isinstance(self.protocol, str):
                proto_map = {'tcp': 6, 'udp': 17, 'icmp': 1}
                if proto_map.get(self.protocol.lower()) != proto_num:
                    return False
            elif self.protocol != proto_num:
                return False
        
        # If we got here, all specified conditions matched
        return True
    
    def _port_match(self, rule_port, packet_port):
        """
        Check if a port matches a rule port specification
        
        Args:
            rule_port: Port specification (can be int, range string, or list)
            packet_port: Actual port from packet
            
        Returns:
            bool: True if port matches, False otherwise
        """
        # Simple integer comparison
        if isinstance(rule_port, int):
            return packet_port == rule_port
            
        # String representation of a single port
        if isinstance(rule_port, str):
            # Check if it's a range like "1000-2000"
            if '-' in rule_port:
                try:
                    start, end = map(int, rule_port.split('-'))
                    return start <= packet_port <= end
                except ValueError:
                    logging.warning(f"Invalid port range: {rule_port}")
                    return False
            
            # Otherwise treat as a single port number
            try:
                return int(rule_port) == packet_port
            except ValueError:
                logging.warning(f"Invalid port specification: {rule_port}")
                return False
                
        # List of ports or ranges
        if isinstance(rule_port, list):
            return any(self._port_match(p, packet_port) for p in rule_port)
            
        # Unknown format
        logging.warning(f"Invalid port specification type: {type(rule_port)}")
        return False


class RuleParser:
    """
    Parser for firewall rules
    """
    
    def __init__(self, rules_list):
        """
        Initialize the rule parser with a list of rules
        
        Args:
            rules_list (list): List of rule dictionaries
        """
        self.logger = logging.getLogger("BasicFirewall.RuleParser")
        self.rules = []
        self.default_action = "allow"
        
        for rule_dict in rules_list:
            try:
                rule = Rule(rule_dict)
                self.rules.append(rule)
            except Exception as e:
                self.logger.error(f"Error parsing rule: {e}")
        
        # Sort rules by priority
        self.rules.sort(key=lambda r: r.priority)
        
        self.logger.info(f"Loaded {len(self.rules)} rules")
    
    def evaluate_packet(self, packet):
        """
        Evaluate a packet against all rules
        
        Args:
            packet: Packet to evaluate
            
        Returns:
            str: Action to take ('allow' or 'block')
        """
        try:
            # Extract packet information for rule evaluation
            # This assumes packet has a method to extract needed info
            if hasattr(packet, 'summary'):
                packet_info = self._extract_packet_info(packet)
                
                # Check each rule in priority order
                for rule in self.rules:
                    if rule.match(packet_info):
                        return rule.action
                        
                # If no rules matched, use default action
                return self.default_action
                
            else:
                self.logger.warning("Received packet without summary method")
                return self.default_action
                
        except Exception as e:
            self.logger.error(f"Error evaluating packet: {e}")
            return "allow"  # Allow on error as a safe default
    
    def _extract_packet_info(self, packet):
        """
        Extract information from a packet for rule evaluation
        
        Args:
            packet: Packet to extract information from
            
        Returns:
            dict: Dictionary with packet information
        """
        packet_info = {}
        
        # Basic extraction for IP layer
        if hasattr(packet, 'src') and hasattr(packet, 'dst'):
            packet_info['src_ip'] = packet.src
            packet_info['dst_ip'] = packet.dst
        
        # Extract protocol information
        if hasattr(packet, 'proto'):
            packet_info['proto'] = packet.proto
        
        # Extract port information if available
        if hasattr(packet, 'sport'):
            packet_info['src_port'] = packet.sport
        if hasattr(packet, 'dport'):
            packet_info['dst_port'] = packet.dport
            
        return packet_info
