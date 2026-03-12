from pathlib import Path
import sys

# generate microkit system file for variable number of clients, with programs named x_i.elf, to specified location
def generate_asynchronous_system_file(number_of_clients, client_names, client_path):
    # memory org vars
    base_vaddr = 0x30000000
    fs_size = 0x10133000
    client_size = 0x81000
        
    output_path = Path(client_path)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    with output_path.open("w") as f:
        f.write("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
        f.write("<system>\n")

        f.write("     <!-- File Server Memory Regions -->\n")
        f.write(f"    <memory_region name=\"fs_memory\" size=\"0x{fs_size:X}\" />\n")
        f.write("\n")
        
        f.write("    <!-- File Server Protection Domain -->\n")
        f.write(f"    <protection_domain name=\"file_server\" priority=\"1\" >\n")
        f.write(f"        <program_image path=\"file_server_multi.elf\"/>\n")
        f.write("\n")

        f.write(f"        <map mr=\"fs_memory\" vaddr=\"0x{base_vaddr:X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"fs_memory_base\"/>\n")

        f.write(f"        <map mr=\"client_0\" vaddr=\"0x{(base_vaddr + fs_size):X}\" perms=\"rw\" cached=\"true\"\n")
        f.write(f"          setvar_vaddr=\"clients_memory_base\"/>\n")
        
        for i in range(1, number_of_clients):
            f.write(f"\n        <map mr=\"client_{i}\" vaddr=\"0x{(base_vaddr + fs_size + i * client_size):X}\" perms=\"rw\" cached=\"true\"/>\n")
        f.write("\n")
        f.write(f"    </protection_domain>\n")

        f.write("\n     <!-- Client Memory Regions -->\n")
        for i in range(number_of_clients):
            f.write(f"    <memory_region name=\"client_{i}\" size=\"0x{client_size:X}\" />\n")
        f.write("\n")
            
        f.write("    <!-- Client Protection Domains -->\n")
        for i in range(number_of_clients):
            f.write(f"    <protection_domain name=\"client_{i}\" priority=\"0\" >\n")
            f.write(f"        <program_image path=\"{client_names}{i}.elf\"/>\n")
            f.write(f"        <map mr=\"client_{i}\" vaddr=\"0x{(base_vaddr):X}\" perms=\"rw\" cached=\"true\"\n")
            f.write(f"          setvar_vaddr=\"fs_data_base\"/>\n")
            f.write(f"    </protection_domain>\n")
            f.write("\n")

        f.write("\n    <!-- Communication Channels -->\n")
        for i in range(number_of_clients):
            f.write(f"    <channel>\n")
            f.write(f"        <end pd=\"file_server\" id=\"{i}\"/>\n")
            f.write(f"        <end pd=\"client_{i}\" id=\"0\" pp=\"true\"/>\n")
            f.write(f"    </channel>\n")

        f.write("</system>\n")

def main(argv):
    if len(argv) != 4:
        print("Usage: python system_generator.py <number_of_clients> <client_names_prefix> <output_path>")
        return 1

    num_clients = int(argv[1])

    if num_clients > 16 or num_clients < 1:
        print("Error: Maximum number of clients is 16.")
        return 1

    generate_asynchronous_system_file(num_clients, argv[2], argv[3])
    return 0

if __name__ == "__main__":
    sys.exit(main(sys.argv))