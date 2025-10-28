import sys

def generate_synchronous_system_file(number_of_clients, buffer_size):
    file_table_size = 10000
    file_data_size = 100000
    file_table_vaddr = 0
    file_data_vaddr = file_table_vaddr + file_table_size
    client_buffer_base_vaddr = file_data_vaddr + file_data_size
        
    with open("file.system", "w") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        f.write("<system>\n")

        f.write("     <!-- File Server Memory Regions -->\n")
        f.write(f"    <memory_region name=\"file_table\" size=\"0x{file_table_size}\" />\n")
        f.write(f"    <memory_region name=\"file_data\" size=\"0x{file_data_size}\" />\n")
        f.write("\n")
        
        f.write("    <!-- File Server Protection Domain -->\n")
        f.write(f"    <protection_domain name=\"file_server\" priority=\"1\" >\n")
        f.write(f"        <program_image path=\"file_server.elf\"/>\n")
        f.write("\n")
        
        f.write(f"        <map mr=\"file_table\" vaddr=\"0x{file_table_vaddr}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"file_table_base\"/>\n")
        f.write(f"        <map mr=\"file_data\" vaddr=\"0x{file_data_vaddr}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"file_data_base\"/>\n")

        f.write(f"        <map mr=\"client_buffer_0\" vaddr=\"0x{client_buffer_base_vaddr}\" perms=\"rw\" cached=\"false\"\n")
        f.write(f"          setvar_vaddr=\"lowest_client_buffer_base\"/>\n")
        
        for i in range(1, number_of_clients):
            f.write(f"        <map mr=\"client_buffer_{i}\" vaddr=\"0x{client_buffer_base_vaddr + i * buffer_size}\" perms=\"rw\" cached=\"false\"/>\n")

        f.write("\n")
        f.write(f"    </protection_domain>\n")

        f.write("\n     <!-- Client Memory Regions -->\n")
        for i in range(number_of_clients):
            # buffer for client
            f.write(f"    <memory_region name=\"client_buffer_{i}\" size=\"0x{buffer_size}\" />\n")
            
        f.write("\n    <!-- Client Protection Domains -->\n")
        for i in range(number_of_clients):
            # client pds
            f.write(f"    <protection_domain name=\"client_{i}\" priority=\"0\" >\n")
            f.write(f"        <program_image path=\"client.elf\"/>\n")
            f.write(f"        <map mr=\"client_buffer_{i}\" vaddr=\"0x0\" perms=\"rw\" cached=\"false\"\n")
            f.write(f"          setvar_vaddr=\"file_server_buffer_base\"/>\n")
            f.write(f"    </protection_domain>\n")
            f.write("\n")

        f.write("\n    <!-- Communication Channels -->\n")
        for i in range(number_of_clients):
            # channels
            f.write(f"    <channel>\n")
            f.write(f"        <end pd=\"file_server\" id=\"{i}\"/>\n")
            f.write(f"        <end pd=\"client_{i}\" id=\"0\" pp=\"true\"/>\n")
            f.write(f"    </channel>\n")

        f.write("</system>\n")


num_clients = int(sys.argv[1])
buffer_size = sys.argv[2] if len(sys.argv) > 2 else 1000
asynchronous = sys.argv[3].lower() == "true" if len(sys.argv) > 3 else False

# maximum PDs is 63
if num_clients > 63 or num_clients < 1:
    print("Error: Maximum number of clients is 63.")
    sys.exit(1)

if not asynchronous:
    generate_synchronous_system_file(num_clients, buffer_size)