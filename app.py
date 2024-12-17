import pyshark
import os
import datetime

pcap_file = 'evidence.pcap'

capture = pyshark.FileCapture(pcap_file)

with open('ouptut.txt','w') as file:

    for packet in capture:
        
        output_path='F:\FYP\my_flask_app'
         
        layers = packet.layers
        
        file.write(f'{packet}\n')
        
        ##Ethernet Layer##
        
        # obtain all the field names within the ETH packets
        field_names = packet.eth._all_fields

        # obtain all the field values
        field_values = packet.eth._all_fields.values()

        # enumerate the field names and field values
        for field_name, field_value in zip(field_names, field_values):
             file.write(f'{field_name}:  {field_value}\n')        

        ##IP Layer##

        field_names = packet.ip._all_fields

        # obtain all the field values
        field_values = packet.ip._all_fields.values()

        # enumerate the field names and field values
        for field_name, field_value in zip(field_names, field_values):
            file.write(f'{field_name}:  {field_value}\n')
    
        ### JAVASCRIPT FILE ####   
        
        if 'HTTP' in str(packet.layers):
         if hasattr(packet.http, 'content_type'): 
           content_type = packet.http.content_type
           ## JS Layer ## 
           if 'application/javascript' in content_type or 'text/javascript' in content_type:
                # Extract the JavaScript content
                js_content = packet.http.file_data 
                # Create a filename based on the packet number
                js_filename = os.path.join(output_path, f"extracted_{packet.number}.js")
                with open(js_filename, 'wb') as js_file:
                    js_file.write(js_content.encode('utf-8'))
            
                field_names = packet.http._all_fields
                field_values = packet.http._all_fields.values()    

                file.write(f"{field_names}:{field_values}\n")

        #IMAGES FILES###
        
        #HTML FILES
        
        if 'HTTP' in str(packet.layers):
            if hasattr(packet.http, 'content_type'): 
                content_type = packet.http.content_type
           ## HTML Text ## 
                if 'text/html' in content_type:
                     # Extract the JavaScript content
                    html_content = packet.http.file_data     
                    
                    html_filename = os.path.join(output_path, f"extracted_{packet.number}.html")
                    with open(html_filename, 'wb') as js_file:
                      js_file.write(html_content.encode('utf-8'))
        
        
        ## HTTP LAYER
        
        if 'HTTP' in str(packet.layers):
            field_names = packet.http._all_fields
            field_values = packet.http._all_fields.values()
            for field_name in field_names:
                for field_value in field_values:
                    if field_name == 'http.request.full_uri' and field_value.startswith('http'):
                        file.write(f'{field_value}\n') 
                            
         # Transport Layer
        
        protocol = packet.transport_layer
        
        # Source details
        source_address = packet.ip.src
        file.write(f'Source Address: {source_address}\n')

        source_port = packet[protocol].srcport
        
        print(source_port)

        # Destination details
        destination_address = packet.ip.dst
        file.write(f'Destination Address: {str(destination_address)}\n')

        destination_port = packet[packet.transport_layer].dstport
        file.write(f'Destination Port: {destination_port}\n')

        packet_time = packet.sniff_time
        file.write(f'Packet Time: {packet_time}\n')

        packet_timestamp = float(packet.sniff_timestamp)
        readable_time = datetime.datetime.fromtimestamp(packet_timestamp)
        file.write(f'Packet Timestamp: {readable_time}\n')
        
