"""
PacketHandler module - handles packet capturing and basic processing
"""

import logging
try:
    import scapy.all as scapy
    HAS_SCAPY = True
except ImportError:
    HAS_SCAPY = False
    logging.warning("Scapy library not found. Limited functionality available.")

class PacketHandler:
    """
    Handles packet capturing and provides interfaces for packet inspection.
    """
    
    def __init__(self, interface=None):
        """
        Initialize the packet handler
        
        Args:
            interface (str): Network interface to capture packets from
        """
        self.interface = interface
        self.logger = logging.getLogger("BasicFirewall.PacketHandler")
        
        if not HAS_SCAPY:
            self.logger.error("Scapy library is required for packet handling")
            raise ImportError("Scapy library is required")
            
    def capture_packets(self):
        """
        Generator that yields captured packets
        
        Yields:
            scapy.packet: Captured network packet
        """
        self.logger.info(f"Starting packet capture on interface: {self.interface or 'default'}")
        
        try:
            # Start packet capture
            packet_count = 0
            
            # Use scapy's sniff function to capture packets
            for packet in scapy.sniff(iface=self.interface, store=False, prn=None):
                packet_count += 1
                yield packet
                
        except Exception as e:
            self.logger.error(f"Error capturing packets: {e}")
            raise
            
    def analyze_packet(self, packet):
        """
        Analyze a packet and extract relevant information
        
        Args:
            packet: The packet to analyze
            
        Returns:
            dict: Dictionary containing packet information
        """
        packet_info = {
            "time": packet.time,
            "length": len(packet),
        }
        
        # Extract IP layer information if present
        if scapy.IP in packet:
            packet_info.update({
                "src_ip": packet[scapy.IP].src,
                "dst_ip": packet[scapy.IP].dst,
                "proto": packet[scapy.IP].proto
            })
        
        # Extract TCP/UDP information if present
        if scapy.TCP in packet:
            packet_info.update({
                "src_port": packet[scapy.TCP].sport,
                "dst_port": packet[scapy.TCP].dport,
                "tcp_flags": packet[scapy.TCP].flags
            })
        elif scapy.UDP in packet:
            packet_info.update({
                "src_port": packet[scapy.UDP].sport,
                "dst_port": packet[scapy.UDP].dport
            })
        
        return packet_info
    
    def get_interfaces(self):
        """
        Get list of available network interfaces
        
        Returns:
            list: List of network interfaces
        """
        if HAS_SCAPY:
            return scapy.get_if_list()
        else:
            self.logger.error("Scapy library is required to get interface list")
            return []
    
    def is_valid_interface(self, interface):
        """
        Check if an interface is valid
        
        Args:
            interface (str): Name of the interface to check
            
        Returns:
            bool: True if interface is valid, False otherwise
        """
        if not interface:
            return False
            
        return interface in self.get_interfaces()
