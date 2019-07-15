import pefile
pe = pefile.PE('/home/osboxes/malware_data_science/ch1/ircbot.exe')
for section in pe.sections:
    print(section.Name, hex(section.VirtualAddress), hex(section.Misc_VirtualSize), section.SizeOfRawData )
pe.parse_data_directories()

for entry in pe.DIRECTORY_ENTRY_IMPORT :
    print entry.dll
    for imp in entry.imports:
        print '\t', hex(imp.address), imp.name

pe.parse_export_directory
for exp in pe.DIRECTORY_ENTRY_EXPORT :
    print (hex(pe.OPTIONAL_HEADER.ImageBase + exp.address), exp.name, exp.ordinal)