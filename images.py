import pyshark
import os
import re

# Path to your PCAP file
pcap_file = 'evidence.pcap'
output_dir = 'F:\FYP'

# Create output directory if not exists
if not os.path.exists(output_dir):
    os.makedirs(output_dir)

def save_image(data, file_name):
    """Save binary data to a file."""
    with open(os.path.join(output_dir, file_name), 'wb') as f:
        f.write(data)

def extract_images_from_pcap(pcap_file):
    """Extract images from PCAP file."""
    cap = pyshark.FileCapture(pcap_file, display_filter='http')  # Filter only HTTP traffic
    
    image_count = 0
    
    for packet in cap:
        try:
            # Check if packet has HTTP response with image content
            if hasattr(packet.http, 'content_type') and 'image' in packet.http.content_type:
                print(f"Found image in packet #{packet.number} with content type: {packet.http.content_type}")
                
                # Extract raw data
                raw_data = packet.http.file_data.binary_value
                if raw_data:
                    # Determine the image extension based on content type
                    ext = 'jpeg' if 'jpeg' in packet.http.content_type else 'png'
                    file_name = f"image_{image_count}.{ext}"
                    save_image(raw_data, file_name)
                    print(f"Saved: {file_name}")
                    image_count += 1

        except AttributeError:
            continue

    print(f"Extracted {image_count} images.")

# Run the extraction
extract_images_from_pcap(pcap_file)
