import pyshark
import os

def extract_js_from_pcap(pcap_file, output_dir):
    # Create output directory if it doesn't exist
    if not os.path.exists(output_dir):
        os.makedirs(output_dir)

    # Load the PCAP file
    cap = pyshark.FileCapture(pcap_file, display_filter='http')
    with open('ouptut.txt','w') as file:
        for packet in cap:
            try:
                # Check if the packet has HTTP layer
                if 'HTTP' in packet:
                    # Check if it's a response and has a content type
                    if hasattr(packet.http, 'content_type'):
                        content_type = packet.http.content_type
                        # Check if the content type is JavaScript
                        if 'application/javascript' in content_type or 'text/javascript' in content_type:
                            # Extract the JavaScript content
                            js_content = packet.http.file_data
                            
                            file.write(f'{packet}\n')
                            
            except Exception as e:
                print(f"Error processing packet: {e}")

# Usage
extract_js_from_pcap('evidence.pcap', 'F:\FYP\my_flask_app')

