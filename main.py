#tested on Model N0120 firmware version 23.2.5
from nmwks_util import *
import argparse


def parse_args():
    parser = argparse.ArgumentParser(
        description="Tool to upload/download files from a Model N0120 calculator."
    )
    parser.add_argument(
        '-d', '--download',
        action='store_true',
        help="Download userland from the calculator to a local directory."
    )
    parser.add_argument(
        '-p', '--prefs',
        action='store_true',
        help="Read or Modify preference files."
    )
    parser.add_argument(
        '-u', '--upload',
        action='store_true',
        help="Upload userland from a local directory to the calculator."
    )
    # A required positional argument for the directory
    parser.add_argument(
        'directory',
        help="Path to the local directory used for upload/download."
    )

    args = parser.parse_args()

    if not (args.download or args.upload or args.prefs):
        parser.error("You must specify at least --download or --upload or --prefs.")

    return args

def main():
    args = parse_args()
    dir_path = args.directory

    # Locate USB device
    dev = usb.core.find(idVendor=0x0483, idProduct=0xa291)
    if dev is None:
        raise ValueError("Device not found. Is it plugged in and accessible?")

    dev.set_configuration()
    try:
        if dev.is_kernel_driver_active(0):
            dev.detach_kernel_driver(0)
    except (NotImplementedError, usb.core.USBError):
        pass

    # Retrieve descriptor information
    print("Get String Descriptors:")
    string_descriptors = retrieve_string_descriptors(dev)
    flash_info = parse_dfu_descriptor(string_descriptors['Flash'])
    sram_info = parse_dfu_descriptor(string_descriptors['SRAM'])
    for i, sec in enumerate(sram_info, start=1):
        size_kb = sec['size'] / 1024.0
        print(f"    SRAM Section {i}: start=0x{sec['start']:08X},"
              f"end=0x{sec['end']:08X}, size={size_kb:.2f} KB")

    print(f"Get slot info from SRAM address: 0x{sram_info[0]['start']:X}")
    set_address_pointer(dev, sram_info[0]['start'])
    dfu_abort(dev)
    results = get_special_data(dev, 16)
    slot_info = parse_slot_info(results)
    for key, value in slot_info.items():
        print(f"  {key}: 0x{value:8X}")

    # Kernel header
    print(f"Get Kernel Header from 0x{slot_info['kernel_header_address']:8x}")
    set_address_pointer(dev, slot_info['kernel_header_address'])
    dfu_abort(dev)
    results = get_special_data(dev, 24)
    kheader_data = parse_kheader(results)
    for key, value in kheader_data.items():
        print(f"  {key}: {value}")

    # Userland header
    print(f"Get Userland Header from 0x{slot_info['userland_header_address']:8x}")
    set_address_pointer(dev, slot_info['userland_header_address'])
    dfu_abort(dev)
    results = get_special_data(dev, 48)
    uheader_data = parse_uheader(results)
    for key, value in uheader_data.items():
        if key == 'version':
            print(f"  {key}: {value}")
        else:
            print(f"  {key}: 0x{value:08x}")

    userland_address = uheader_data['sram_address']
    userland_size = uheader_data['sram_size']


    if args.download:
        print(f"\n[DOWNLOAD] Dumping {userland_size} bytes from 0x{userland_address:8x} to '{dir_path}'")
        download(dev, userland_address, userland_size, dir_path)

    if args.prefs:
        pr_filename = f"{dir_path}/pr.sys"
        prefs = read_preferences(pr_filename)
        print(f"Preferences read from {pr_filename}")
        for k, v in prefs.items():
            print(f"  {k}: {v}")

        gp_filename = f"{dir_path}/gp.sys"
        gp = read_global_preferences(gp_filename)
        print(f"GlobalPreferences read from {gp_filename}")
        for k, v in gp.items():
            print(f"  {k}: {v}")

        #example of changing settings
        #gp["brightnessLevel"] = 80 # Change Brightness

        write_preferences(prefs, pr_filename)
        print(f"Preferences updated and written back to {pr_filename}")

        write_global_preferences(gp, gp_filename)
        print(f"GlobalPreferences updated and written back to {gp_filename}")

    # Perform upload if requested
    if args.upload:
        print(f"\n[UPLOAD] Uploading {userland_size} bytes from '{dir_path}' back to address 0x{userland_address:8x}")
        upload(dev, userland_address, userland_size, dir_path)

if __name__ == "__main__":
    main()
