#!/usr/bin/env python3
import argparse
import pefile



def inject_stub(pe_file, stub_file):
    print("[*] Reading PE file...")
    with open(pe_file, "rb") as f:
        pe_file_contents = f.read()
    print("[*] Anal. PE file...")

    pe_data = pefile.PE(pe_file)
    dos_header_dict = pe_data.DOS_HEADER.dump_dict()
    pe_offset = dos_header_dict.get("e_lfanew")['Value']
    old_dos_stub_size = pe_offset - 64
    old_pe_dos_stub = pe_file_contents[64:pe_offset]
    
    print("[*] Reading DOS stub file...")
    with open(stub_file, 'rb') as f:
        dos_stub_contents = f.read()
    print("[*] Replacing and writing stub...")

    with open(pe_file, 'r+b') as f:
        if(len(dos_stub_contents) > old_dos_stub_size):
            f.seek(0x3d)
            f.write(bytes((len(dos_stub_contents) + ((len(dos_stub_contents) - old_dos_stub_size)))))
        f.seek(64)
        f.write(dos_stub_contents)
        
    


    



def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("PE", help="File path of the PE file to modify", type=str)
    parser.add_argument("DOS_STUB", help="File path of the DOS STUB to 'inject' into the PE", default="stub.bin")
    # parser.add_argument("--output", help="Optionally specify the output file instead of default")
    # @TODO add output instead of in place modification
    
    args = parser.parse_args()
    
    # out = ""
    # if(args.output):
    #     out = args.output
    # else:
    #     out = args.PE + ".injected"
    inject_stub(args.PE, args.DOS_STUB)

    pass



if __name__ == '__main__':
    main()
