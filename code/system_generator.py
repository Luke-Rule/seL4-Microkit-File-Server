import sys

def generate_synchronous_system_file(number_of_clients):
    client_buffer_base_vaddr = 0x30000000
    op_queue_size = 0x1000
    buffer_size = 0x40000
    fs_base = 0x4000000
    block_table_size = 0x1F000
    i_node_table_size = 0x5B8000
    file_descriptor_table_size = 0x2F4000
    blocks_size = 0x1F018000
        
    with open("/home/luker/project/seL4-Microkit-File-Server/code/fs_tests.system", "w") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        f.write("<system>\n")

        f.write("     <!-- File Server Memory Regions -->\n")
        f.write(f"    <memory_region name=\"block_table\" size=\"0x{block_table_size:X}\" />\n")
        f.write(f"    <memory_region name=\"i_node_table\" size=\"0x{i_node_table_size:X}\" />\n")
        f.write(f"    <memory_region name=\"file_descriptor_table\" size=\"0x{file_descriptor_table_size:X}\" />\n")
        f.write(f"    <memory_region name=\"blocks\" size=\"0x{blocks_size:X}\" />\n")
        f.write("\n")
        
        f.write("    <!-- File Server Protection Domain -->\n")
        f.write(f"    <protection_domain name=\"file_server_dynamic\" priority=\"1\" >\n")
        f.write(f"        <program_image path=\"file_server_dynamic.elf\"/>\n")
        f.write("\n")

        f.write(f"        <map mr=\"block_table\" vaddr=\"0x{fs_base:X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"block_table_base\"/>\n")
        f.write(f"        <map mr=\"file_descriptor_table\" vaddr=\"0x{fs_base + block_table_size:X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"file_descriptor_table_base\"/>\n")
        f.write(f"        <map mr=\"i_node_table\" vaddr=\"0x{fs_base + block_table_size + file_descriptor_table_size:X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"i_node_table_base\"/>\n")
        f.write(f"        <map mr=\"blocks\" vaddr=\"0x{fs_base + block_table_size + file_descriptor_table_size + i_node_table_size:X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"blocks_base\"/>\n\n")

        f.write(f"        <map mr=\"client_submission_queue_0\" vaddr=\"0x{client_buffer_base_vaddr:X}\" perms=\"r\" cached=\"false\"\n")
        f.write(f"          setvar_vaddr=\"lowest_client_queue_base\"/>\n")
        f.write(f"        <map mr=\"client_completion_queue_0\" vaddr=\"0x{(client_buffer_base_vaddr + op_queue_size):X}\" perms=\"rw\" cached=\"false\"/>\n")
        f.write(f"        <map mr=\"client_submission_buffer_0\" vaddr=\"0x{(client_buffer_base_vaddr + 2 * op_queue_size):X}\" perms=\"r\" cached=\"false\"/>\n")
        f.write(f"        <map mr=\"client_completion_buffer_0\" vaddr=\"0x{(client_buffer_base_vaddr + 2 * op_queue_size + buffer_size):X}\" perms=\"rw\" cached=\"false\"/>\n")
        
        for i in range(1, number_of_clients):
            starting_offset = i * 2 * (buffer_size + op_queue_size)
            f.write(f"\n        <map mr=\"client_submission_queue_{i}\" vaddr=\"0x{(client_buffer_base_vaddr + starting_offset):X}\" perms=\"r\" cached=\"false\"/>\n")
            f.write(f"        <map mr=\"client_completion_queue_{i}\" vaddr=\"0x{(client_buffer_base_vaddr + starting_offset + op_queue_size):X}\" perms=\"rw\" cached=\"false\"/>\n")
            f.write(f"        <map mr=\"client_submission_buffer_{i}\" vaddr=\"0x{(client_buffer_base_vaddr + starting_offset + 2 * op_queue_size):X}\" perms=\"r\" cached=\"false\"/>\n")
            f.write(f"        <map mr=\"client_completion_buffer_{i}\" vaddr=\"0x{(client_buffer_base_vaddr + starting_offset + 2 * op_queue_size + buffer_size):X}\" perms=\"rw\" cached=\"false\"/>\n")
        f.write("\n")
        f.write(f"    </protection_domain>\n")

        f.write("\n     <!-- Client Memory Regions -->\n")
        for i in range(number_of_clients):
            # buffer for client
            f.write(f"    <memory_region name=\"client_submission_queue_{i}\" size=\"0x{op_queue_size:X}\" />\n")
            f.write(f"    <memory_region name=\"client_completion_queue_{i}\" size=\"0x{op_queue_size:X}\" />\n")
            f.write(f"    <memory_region name=\"client_submission_buffer_{i}\" size=\"0x{buffer_size:X}\" />\n")
            f.write(f"    <memory_region name=\"client_completion_buffer_{i}\" size=\"0x{buffer_size:X}\" />\n\n")
        f.write("\n")
            
        f.write("    <!-- Client Protection Domains -->\n")
        for i in range(number_of_clients):
            # client pds
            f.write(f"    <protection_domain name=\"client_{i}\" priority=\"0\" >\n")
            f.write(f"        <program_image path=\"fs_tests.elf\"/>\n")
            f.write(f"        <map mr=\"client_submission_queue_{i}\" vaddr=\"0x0\" perms=\"rw\" cached=\"false\"\n")
            f.write(f"          setvar_vaddr=\"file_server_submission_queue_base\"/>\n")
            f.write(f"        <map mr=\"client_completion_queue_{i}\" vaddr=\"0x{op_queue_size:X}\" perms=\"r\" cached=\"false\"\n")
            f.write(f"          setvar_vaddr=\"file_server_completion_queue_base\"/>\n")
            f.write(f"        <map mr=\"client_submission_buffer_{i}\" vaddr=\"0x{(2 * op_queue_size):X}\" perms=\"rw\" cached=\"false\"\n")
            f.write(f"          setvar_vaddr=\"file_server_submission_buffer_base\"/>\n")
            f.write(f"        <map mr=\"client_completion_buffer_{i}\" vaddr=\"0x{(2 * op_queue_size + buffer_size):X}\" perms=\"r\" cached=\"false\"\n")
            f.write(f"          setvar_vaddr=\"file_server_completion_buffer_base\"/>\n")
            f.write(f"    </protection_domain>\n")
            f.write("\n")

        f.write("\n    <!-- Communication Channels -->\n")
        for i in range(number_of_clients):
            # channels
            f.write(f"    <channel>\n")
            f.write(f"        <end pd=\"file_server_dynamic\" id=\"{i}\"/>\n")
            f.write(f"        <end pd=\"client_{i}\" id=\"0\" pp=\"true\"/>\n")
            f.write(f"    </channel>\n")

        f.write("</system>\n")


num_clients = int(sys.argv[1])

# maximum PDs is 63
if num_clients > 16 or num_clients < 1:
    print("Error: Maximum number of clients is 16.")
    sys.exit(1)

generate_synchronous_system_file(num_clients)