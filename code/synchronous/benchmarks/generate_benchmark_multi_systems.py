from pathlib import Path
import sys

from system_generator import generate_synchronous_system_file

PARENT_DIR = Path(__file__).resolve().parent.parent
if str(PARENT_DIR) not in sys.path:
    sys.path.insert(0, str(PARENT_DIR))

DEFAULT_CLIENT_PREFIX = "multi_client_"
DEFAULT_OUTPUT_DIR = Path(__file__).resolve().parent / "systems"

def main(argv):
    if len(argv) > 3:
        print("Usage: python generate_benchmark_multi_systems.py [client_names_prefix] [output_dir]")
        return 1

    client_prefix = argv[1] if len(argv) >= 2 else DEFAULT_CLIENT_PREFIX
    output_dir = Path(argv[2]) if len(argv) == 3 else DEFAULT_OUTPUT_DIR
    output_dir.mkdir(parents=True, exist_ok=True)

    for client_count in range(2, 17):
        output_path = output_dir / f"{client_count}.system"
        generate_synchronous_system_file(client_count, client_prefix, output_path)

    print(f"Generated system files 2.system through 16.system in {output_dir}")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))