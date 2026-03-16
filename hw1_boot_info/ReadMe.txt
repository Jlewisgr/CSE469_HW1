Name: Jagger Lewis-Grenz
ASU ID: 1225110172

Description:
This program analyzes raw forensic disk images and determines whether the
image uses MBR or GPT partitioning. It calculates MD5, SHA-256, and SHA-512
hashes of the disk image before opening it. If the image uses MBR, the program
parses the partition table and prints partition type, starting sector, and
partition size. It also reads the boot record of each partition and prints
16 bytes from a specified offset in both hexadecimal and ASCII format.
If the image uses GPT, the program reads the GPT header and partition entries
and prints the partition type GUID, starting and ending LBAs, partition name,
and partition size in bytes.

Generative AI Acknowledgment:
Github copilot was used while coding to generate some suggestions when it came
bug fixes and while writing code it gave a few suggestions for structure.

Reference:
GitHub. (2024). GitHub Copilot [AI coding assistant]. https://github.com/features/copilot