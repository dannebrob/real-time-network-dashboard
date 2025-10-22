import streamlit as st
import pandas as pd
import plotly.express as px
import plotly.graph_objects as go
from scapy.all import *
from collections import defaultdict, deque
import time
from datetime import datetime
import threading
import warnings
import logging
from typing import Dict, List, Optional
import socket

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)

class PacketProcessor:
    """Process and analyze network packets"""

    def __init__(self, verbose: bool = False):
        self.protocol_map = {
            1: 'ICMP',
            6: 'TCP',
            17: 'UDP'
        }
        self.packet_data = deque(maxlen=10000)
        self.start_time = datetime.now()
        self.packet_count = 0
        self.lock = threading.Lock()
        self.verbose = verbose

    def get_protocol_name(self, protocol_num: int) -> str:
        """Convert protocol number to name"""
        return self.protocol_map.get(protocol_num, f'OTHER({protocol_num})')

    def process_packet(self, packet) -> None:
        """Process a single packet and extract relevant information"""
        try:
            if IP in packet:
                with self.lock:
                    packet_info = {
                        'timestamp': datetime.now(),
                        'source': packet[IP].src,
                        'destination': packet[IP].dst,
                        'protocol': self.get_protocol_name(packet[IP].proto),
                        'size': len(packet),
                        'time_relative': (datetime.now() - self.start_time).total_seconds()
                    }

                    # Add TCP-specific information
                    if TCP in packet:
                        packet_info.update({
                            'src_port': packet[TCP].sport,
                            'dst_port': packet[TCP].dport,
                            'tcp_flags': packet[TCP].flags
                        })

                    # Add UDP-specific information
                    elif UDP in packet:
                        packet_info.update({
                            'src_port': packet[UDP].sport,
                            'dst_port': packet[UDP].dport
                        })

                    self.packet_data.append(packet_info)
                    self.packet_count += 1

                    # Debug output to terminal
                    logger.info(f"Processed packet #{self.packet_count}: {packet_info}")
                    if self.verbose:
                        print(f"[DEBUG] {packet_info}")
                    # Debug output to terminal (log every 100th packet at DEBUG level)
                    if self.packet_count % 100 == 0:
                        logger.debug(f"Processed packet #{self.packet_count}: {packet_info}")
                    if self.verbose:
                        print(f"[DEBUG] {packet_info}")
        except Exception as e:
            # Log exception with stack trace and optionally print in verbose mode
            logger.exception(f"Exception while processing packet: {e}")
            if self.verbose:
                print(f"[ERROR] Exception while processing packet: {e}")
    def get_dataframe(self) -> pd.DataFrame:
        """Convert packet data to pandas DataFrame"""
        with self.lock:
            return pd.DataFrame(self.packet_data)
        
def create_visualizations(df: pd.DataFrame):
    """Create all dashboard visualizations"""
    if df is None or df.empty:
        st.info("No packet data to display yet.")
        return

    # Protocol distribution
    protocol_counts = df['protocol'].value_counts()
    fig_protocol = px.pie(
        values=protocol_counts.values,
        names=protocol_counts.index,
        title="Protocol Distribution"
    )
    st.plotly_chart(fig_protocol, use_container_width=True)

    # Packets timeline
    df_timeline = df.copy()
    df_timeline['timestamp'] = pd.to_datetime(df_timeline['timestamp'])
    df_grouped = df_timeline.groupby(df_timeline['timestamp'].dt.floor('s')).size()
    fig_timeline = px.line(
        x=df_grouped.index,
        y=df_grouped.values,
        title="Packets per Second"
    )
    st.plotly_chart(fig_timeline, use_container_width=True)

    # Top source IP addresses
    top_sources = df['source'].value_counts().head(10)
    fig_sources = px.bar(
        x=top_sources.index,
        y=top_sources.values,
        title="Top Source IP Addresses"
    )
    st.plotly_chart(fig_sources, use_container_width=True)
        
def start_packet_capture(verbose: bool = False, iface: Optional[str] = None, count: Optional[int] = None, timeout: Optional[int] = None):
    """Start packet capture in a separate thread with optional constraints and return a PacketProcessor."""
    processor = PacketProcessor(verbose=verbose)

    def capture_packets():
        sniff(
            prn=processor.process_packet,
            store=False,
            iface=iface,
            count=count,
            timeout=timeout
        )

    capture_thread = threading.Thread(target=capture_packets, daemon=True)
    capture_thread.start()

    return processor

def main():
    st.title("Real-time Network Traffic Analysis Dashboard")

    # Sidebar controls
    debug_verbose = st.sidebar.checkbox("Enable verbose prints (terminal)", value=False)
    iface = st.sidebar.text_input("Network Interface (leave blank for default)", value="")
    count = st.sidebar.number_input("Packet Count Limit (0 = unlimited)", min_value=0, value=0)
    timeout = st.sidebar.number_input("Capture Timeout (seconds, 0 = unlimited)", min_value=0, value=0)

    # Convert blank/zero values to None for sniff()
    iface_param = iface.strip() or None
    count_param = count if count > 0 else None
    timeout_param = timeout if timeout > 0 else None

    # Initialize packet processor in session state (only once)
    if 'processor' not in st.session_state:
        st.session_state.processor = start_packet_capture(
            verbose=debug_verbose,
            iface=iface_param,
            count=count_param,
            timeout=timeout_param
        )
        st.session_state.start_time = time.time()
    else:
        # Update the verbose attribute if the checkbox is toggled
        st.session_state.processor.verbose = debug_verbose

    # Provide a button to simulate a packet (useful when sniff isn't capturing)
    if st.button("Simulate Packet"):
        # Use RFC 5737 TEST-NET addresses and descriptive port variables
        TEST_SRC_IP = "192.0.2.1"        # TEST-NET-1
        TEST_DST_IP = "198.51.100.1"     # TEST-NET-2
        TEST_SRC_PORT = 12345
        TEST_DST_PORT = 80
        # create a simple synthetic TCP packet and process it in the same thread
        pkt = IP(src=TEST_SRC_IP, dst=TEST_DST_IP)/TCP(sport=TEST_SRC_PORT, dport=TEST_DST_PORT)
        st.session_state.processor.process_packet(pkt)
        st.success("Simulated packet injected (check terminal output)")

    # Create dashboard layout
    col1, col2 = st.columns(2)

    # Get current data
    df = st.session_state.processor.get_dataframe()

    # Display metrics
    with col1:
        st.metric("Total Packets", len(df))
    with col2:
        duration = time.time() - st.session_state.start_time
        st.metric("Capture Duration", f"{duration:.2f}s")

    # Display visualizations
    create_visualizations(df)

    # Display recent packets
    st.subheader("Recent Packets")
    if len(df) > 0:
        st.dataframe(
            df.tail(10)[['timestamp', 'source', 'destination', 'protocol', 'size']],
            use_container_width=True
        )

    # Add refresh button
    if st.button('Refresh Data'):
        st.rerun()

    # Auto refresh commented out; enable if desired
    # time.sleep(2)
    # st.rerun()

logger.info("Starting Real-time Network Traffic Analysis Dashboard")

if __name__ == '__main__':
    logger.info("Starting Real-time Network Traffic Analysis Dashboard")
    main()