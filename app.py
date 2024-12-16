import pyshark
import datetime

pcap_file = 'evidence.pcap'

capture = pyshark.FileCapture(pcap_file)

with open('ouptut.txt','w') as file:

    for packet in capture:
        
        # ##Ethernet Layer##
        
        # # obtain all the field names within the ETH packets
        # field_names = packet.eth._all_fields

        # # obtain all the field values
        # field_values = packet.eth._all_fields.values()

        # # enumerate the field names and field values
        # for field_name, field_value in zip(field_names, field_values):
        #     file.write(f'{field_name}:  {field_value}\n')        

        # ##IP Layer##

        # field_names = packet.ip._all_fields

        # # obtain all the field values
        # field_values = packet.ip._all_fields.values()

        # # enumerate the field names and field values
        # for field_name, field_value in zip(field_names, field_values):
        #     file.write(f'{field_name}:  {field_value}\n')
    
    
        ## Transport Layer
        protocol = packet.transport_layer
    
        # file.write(f'Protocol: {protocol}\n')

        # # Source details
        # source_address = packet.ip.src
        # file.write(f'Source Address: {source_address}\n')

        source_port = packet[protocol].srcport
        
        print(source_port)

        # # Destination details
        # destination_address = packet.ip.dst
        # file.write(f'Destination Address: {destination_address}\n')

        # destination_port = packet[packet.transport_layer].dstport
        # file.write(f'Destination Port: {destination_port}\n')

        # # Time details
        # packet_time = packet.sniff_time
        # file.write(f'Packet Time: {packet_time}\n')

        # packet_timestamp = float(packet.sniff_timestamp)
        # readable_time = datetime.datetime.fromtimestamp(packet_timestamp)
        # file.write(f'Packet Timestamp: {readable_time}\n')
        
        
        # if 'HTTP' in packet:
        #         file.write("### HTTP Layer Data ###\n")
        #         for field_name, field_value in packet.http._all_fields.items():
        #             file.write(f'{field_name}: {field_value}\n')
        

#  layers = packet.layers
#     print(layers)