import sys
# TODO: cache or not?
def generate_synchronous_system_file(number_of_clients):
    base_vaddr = 0x30000000
    
    fs_size = 0x10133000
    client_size = 0x81000
        
    with open("/home/luker/project/seL4-Microkit-File-Server/code/fs_tests.system", "w") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        f.write("<system>\n")

        f.write("     <!-- File Server Memory Regions -->\n")
        f.write(f"    <memory_region name=\"fs_memory\" size=\"0x{fs_size:X}\" />\n")
        f.write("\n")
        
        f.write("    <!-- File Server Protection Domain -->\n")
        f.write(f"    <protection_domain name=\"file_server\" priority=\"1\" >\n")
        f.write(f"        <program_image path=\"file_server.elf\"/>\n")
        f.write("\n")

        f.write(f"        <map mr=\"fs_memory\" vaddr=\"0x{base_vaddr:X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"fs_memory_base\"/>\n")

        f.write(f"        <map mr=\"client_0\" vaddr=\"0x{(base_vaddr + fs_size):X}\" perms=\"rw\" cached=\"false\"\n")
        f.write(f"          setvar_vaddr=\"clients_memory_base\"/>\n")
        
        for i in range(1, number_of_clients):
            f.write(f"\n        <map mr=\"client_base{i}\" vaddr=\"0x{(base_vaddr + fs_size + i * client_size):X}\" perms=\"rw\" cached=\"false\"/>\n")
        f.write("\n")
        f.write(f"    </protection_domain>\n")

        f.write("\n     <!-- Client Memory Regions -->\n")
        for i in range(number_of_clients):
            f.write(f"    <memory_region name=\"client_{i}\" size=\"0x{client_size:X}\" />\n")
        f.write("\n")
            
        f.write("    <!-- Client Protection Domains -->\n")
        for i in range(number_of_clients):
            # client pds
            f.write(f"    <protection_domain name=\"client_{i}\" priority=\"0\" >\n")
            f.write(f"        <program_image path=\"client{i}.elf\"/>\n")
            f.write(f"        <map mr=\"client_{i}\" vaddr=\"0x{(base_vaddr):X}\" perms=\"rw\" cached=\"false\"\n")
            f.write(f"          setvar_vaddr=\"fs_data_base\"/>\n")
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

if num_clients > 16 or num_clients < 1:
    print("Error: Maximum number of clients is 16.")
    sys.exit(1)

generate_synchronous_system_file(num_clients)