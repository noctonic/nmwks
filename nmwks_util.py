import usb.core
import usb.util
import time
import struct
import os
import math
import re

def address_to_list(address):
    return list(struct.pack('<I', address))


def get_device_descriptor(dev):
    descriptor_info = {}
    try:
        device_desc = dev.ctrl_transfer(
            0x80,    # bmRequestType (Device-to-host, Standard, Device)
            0x06,    # bRequest = GET_DESCRIPTOR
            (0x01 << 8) | 0,  # wValue = (DescriptorType << 8) | DescriptorIndex
            0x0000,  # wIndex (for Device Descriptor, usually 0)
            18       # wLength (typical size of a Device Descriptor)
        )

        descriptor_info["bLength"]             = device_desc[0]
        descriptor_info["bDescriptorType"]     = device_desc[1]
        descriptor_info["bcdUSB"]              = device_desc[2] | (device_desc[3] << 8)
        descriptor_info["bDeviceClass"]        = device_desc[4]
        descriptor_info["bDeviceSubClass"]     = device_desc[5]
        descriptor_info["bDeviceProtocol"]     = device_desc[6]
        descriptor_info["bMaxPacketSize0"]     = device_desc[7]
        descriptor_info["idVendor"]            = device_desc[8] | (device_desc[9] << 8)
        descriptor_info["idProduct"]           = device_desc[10] | (device_desc[11] << 8)
        descriptor_info["bcdDevice"]           = device_desc[12] | (device_desc[13] << 8)
        descriptor_info["iManufacturer"]       = device_desc[14]
        descriptor_info["iProduct"]            = device_desc[15]
        descriptor_info["iSerialNumber"]       = device_desc[16]
        descriptor_info["bNumConfigurations"]  = device_desc[17]

    except usb.core.USBError as e:
        descriptor_info["error"] = f"Error retrieving Device Descriptor: {e}"

    return descriptor_info

def retrieve_single_string_descriptor(dev, index):

    data = dev.ctrl_transfer(
        0x80,                # bmRequestType: Device-to-host, Standard, Device
        0x06,                # bRequest: GET_DESCRIPTOR
        (0x03 << 8) | index, # wValue: (STRING descriptor << 8) + index
        0x0409,              # wIndex: English (United States)
        255                  # wLength: maximum length for string descriptors
    )
    return data[2:].tobytes().decode('utf-16-le', errors='replace')


def retrieve_string_descriptors(dev):
    desc_dict = {}
    
    descriptor_map = {
        1: "iManufacturer",
        2: "iProduct",
        3: "iSerialNumber",
        4: "Flash",
        5: "SRAM"
    }

    for index, key in descriptor_map.items():
        desc_dict[key] = retrieve_single_string_descriptor(dev, index)

    return desc_dict

def parse_dfu_descriptor(dfu_string):
    dfu_string = dfu_string.strip()
    parts = dfu_string.split('/')
    if len(parts) < 3:
        return []

    try:
        current_address = int(parts[1], 16)
    except ValueError:
        return []

    # The third part should look like "61*064Kg,64*064Kg"
    segments_text = parts[2]
    segment_defs = [s.strip() for s in segments_text.split(',')]
    pattern = re.compile(r'^(\d+)\*(\d+)([Kk])')

    sections = []

    for seg_def in segment_defs:
        match = pattern.match(seg_def)
        if not match:
            continue

        num_sectors = int(match.group(1))      # e.g. "61"
        sector_size_kb = int(match.group(2))   # e.g. "064" => 64
        total_size = num_sectors * sector_size_kb * 1024

        end_address = current_address + total_size - 1

        sections.append({
            "start": current_address,
            "end": end_address,
            "size": total_size
        })

        current_address += total_size

    return sections

def dfu_abort(dev,timeout=1000):
    dev.ctrl_transfer(
        0x21,   # Host-to-device, Class, Interface
        6,      # bRequest = DFU_ABORT
        0,      # wValue
        0,      # wIndex
        None,   # No data payload
        timeout=timeout
    )

def dfu_upload_block(dev, block_number, length, timeout=5000):

    data = dev.ctrl_transfer(
        0xA1,              # Device-to-Host, Class, Interface
        2,                 # bRequest = DFU_UPLOAD
        block_number,      # wValue = block number
        0,                 # wIndex = interface number
        length,            # wLength = number of bytes to read
        timeout=timeout
    )
    return data

def dfu_download_block(dev, block_number, data,timeout=5000):
    dev.ctrl_transfer(
        0x21,             # Host-to-Device, Class, Interface
        0x01,             # bRequest = DFU_DNLOAD
        block_number,     # wValue = block number
        0,                # wIndex = interface
        data,             # The payload as a list or bytes
        timeout=timeout
    )

def dfu_get_state(dev):
    DFU_STATES = {
        0: "appIDLE",
        1: "appDETACH",
        2: "dfuIDLE",
        3: "dfuDNLOAD-SYNC",
        4: "dfuDNLOAD-BUSY",
        5: "dfuDNLOAD-IDLE",
        6: "dfuMANIFEST-SYNC",
        7: "dfuMANIFEST",
        8: "dfuMANIFEST-WAIT-RESET",
        9: "dfuUPLOAD-IDLE",
        10: "dfuERROR",
    }
    data = dev.ctrl_transfer(
            0xA1,  # Device-to-host, Class, Interface
            5,     # DFU_GETSTATE
            0,     # wValue
            0,     # interface = 0
            1      # wLength = 1
        )

    if data:
        state_byte = data[0]
        state_str = DFU_STATES.get(state_byte, f"Unknown (0x{state_byte:02X})")
        return state_byte, state_str
    else:
        return None, "No data"

def dfu_get_status(dev, timeout=1000):
    data = dev.ctrl_transfer(
        0xA1,
        3,  # DFU_GETSTATUS
        0,
        0,
        6,
        timeout=timeout
    )

    bStatus = data[0]
    bwPollTimeout = data[1] | (data[2] << 8) | (data[3] << 16)
    bState = data[4]
    iString = data[5]

    return (bStatus, bwPollTimeout, bState, iString)

def wait_for_status(dev):
    while True:
        bStatus, bwPollTimeout, bState, iString = dfu_get_status(dev)
        if bwPollTimeout > 0:
            time.sleep(bwPollTimeout / 1000.0)

        if bState == 0x05:  # dfuDNLOAD-IDLE
            return
        elif bState == 0x0A:  # dfuERROR
            print("Device entered dfuERROR state!")
            return
        else:
            pass

def wait_for_idle_or_error(dev, poll_interval=0.25, max_attempts=40):
    attempts = 0
    while attempts < max_attempts:
        try:
            state_byte, state_str = dfu_get_state(dev)
        except usb.core.USBError as e:
            print(f"Error getting DFU state: {e}")
            return None, "USBError"

        if state_byte is None:
            print("No data returned from DFU GetState.")
            return None, "No data"
        
        if state_str == "dfuIDLE" or state_str == "dfuERROR":
            return state_byte, state_str
        
        time.sleep(poll_interval)
        attempts += 1

    print(f"Timeout: Device did not reach dfuIDLE or dfuERROR after {max_attempts} attempts.")
    return None, "Timeout"

def dfu_download_and_wait_idle(dev, block_num, data):
    dfu_download_block(dev, block_num, data)
    wait_for_status(dev)

def set_address_pointer(dev,address):
    '''
    DFUDownloadCommand {
      GetCommand         = 0x00,
      SetAddressPointer  = 0x21,
      Erase              = 0x41,
      ReadUnprotect      = 0x92

    '''
    cmd = [0x21]
    address = address_to_list(address)
    data = cmd + address
    upload_block_num=2 
    upload_length=24

    dfu_download_and_wait_idle(dev, block_num=0, data=data)

def get_special_data(dev,upload_length):
    upload_block_num = 2
    state_byte, state_str = wait_for_idle_or_error(dev)
    if state_str not in ["dfuIDLE", "dfuERROR"]:
        dfu_abort(dev)
        return None
    if state_str == "dfuERROR":
        print("Device is in dfuERROR state; aborting operation.")
        return None
    try:
        response_data = dfu_upload_block(dev, upload_block_num, upload_length)
    except usb.core.USBError as e:
        print(f"DFU Upload block #{upload_block_num} error: {e}")
        return None

    dfu_abort(dev)
    return response_data

def parse_slot_info(slot_bytes: bytes):
    # Unpack as big-endian 32-bit integers
    kernel_header_addr, userland_header_addr = struct.unpack('<II', slot_bytes[4:-4])

    return {
        "kernel_header_address" : kernel_header_addr,
        "userland_header_address": userland_header_addr,
    }

def parse_kheader(kheader_bytes):

    magic_prefix, = struct.unpack(">I", kheader_bytes[0:4])
    if magic_prefix != 0xF00DC0DE:
        raise ValueError("Invalid magic prefix (expected 0xF00DC0DE).")

    version_raw = kheader_bytes[4:12]
    version_str = bytes(version_raw).rstrip(b"\x00").decode("ascii")

    mystery_string_raw = kheader_bytes[12:20]
    mystery_string_str = bytes(mystery_string_raw).rstrip(b"\x00").decode("ascii")

    magic_suffix, = struct.unpack(">I", kheader_bytes[-4:])
    return {
        "version":       version_str,
        "mystery_string": mystery_string_str,
    }

def parse_uheader(uheader_bytes):
    if len(uheader_bytes) != 48:
        raise ValueError(f"Expected 48 bytes, got {len(uheader_bytes)}")

    magic_prefix, = struct.unpack(">I", uheader_bytes[0:4])
    if magic_prefix != 0xFEEDC0DE:
        raise ValueError("Invalid magic prefix (expected 0xFEEDC0DE).")
    magic_suffix, = struct.unpack(">I", uheader_bytes[-4:])
    if magic_suffix != 0xFEEDC0DE:
        raise ValueError("Invalid magic prefix (expected 0xFEEDC0DE).")
    version_raw = uheader_bytes[4:12]
    version_str = bytes(version_raw).rstrip(b"\x00").decode("ascii")

    fields = struct.unpack("<IIIIIIII", uheader_bytes[12:-4])
    (
        sram_address,
        sram_size,
        flash_address,
        flash_end,
        extra1,
        extra2,
        extra3,
        extra4
    ) = fields

    if magic_suffix != 0xFEEDC0DE:
        raise ValueError("Invalid magic suffix (expected 0xFEEDC0DE).")

    return {

        "version":       version_str,
        "sram_address":  sram_address,
        "sram_size":     sram_size,
        "flash_address": flash_address,
        "flash_end":     flash_end,
        "extra1":        extra1,
        "extra2":        extra2,
        "extra3":        extra3,
        "extra4":        extra4

    }


def dump_scripts(dev, address, size):

    magic = 8
    total_size = size + magic  
    block_size = 2048

    wait_for_idle_or_error(dev)
    set_address_pointer(dev, address)
    dfu_abort(dev)

    num_blocks = (total_size + (block_size - 1)) // block_size

    final_output = b''

    for i in range(num_blocks):
        block_num = 2 + i

        this_upload_length = block_size

        if i == (num_blocks - 1):
            remainder = total_size % block_size
            if remainder != 0:
                this_upload_length = remainder

        try:
            response_data = dfu_upload_block(dev, block_num, this_upload_length)
            final_output += response_data
        except usb.core.USBError:
            return None

    dfu_abort(dev)
    wait_for_idle_or_error(dev)
    return final_output


def parse_memory_blocks(memory_blocks: bytes):
    MAGIC = b'\xba\xdd\x0b\xee'

    offset = 0
    length = len(memory_blocks)
    records = []

    if length < 4:
        raise ValueError("Memory too short to contain the initial MAGIC bytes.")
    first_magic = memory_blocks[offset : offset + 4]
    if first_magic != MAGIC:
        raise ValueError(f"Invalid magic at start: {first_magic} != {MAGIC}")
    offset += 4

    while offset < length:
        maybe_magic = memory_blocks[offset : offset + 4]
        if maybe_magic == MAGIC:
            break

        if offset + 2 > length:
            raise ValueError("Truncated data: cannot read record size.")
        size_bytes = memory_blocks[offset : offset + 2]
        record_size = struct.unpack('<H', size_bytes)[0]
        offset += 2

        if record_size == 0:
            next_magic_loc = memory_blocks.find(MAGIC, offset)
            if next_magic_loc < 0:
                next_magic_loc = length

            num_pad_bytes = next_magic_loc - offset

            records.append({
                'record_length': 2 + num_pad_bytes,
                'full_name': 'PADDING',
                'body': b''
            })

            # Skip over the padding
            offset += num_pad_bytes

            continue

        data_length = record_size - 2
        if data_length < 0:
            raise ValueError(
                f"Invalid record size: {record_size} (must be >= 2)."
            )
        if offset + data_length > length:
            raise ValueError(
                f"Truncated data: needed {data_length} bytes but only "
                f"{length - offset} remain."
            )

        record_data = memory_blocks[offset : offset + data_length]
        offset += data_length

        null_pos = record_data.find(b'\x00')
        if null_pos < 0:
            raise ValueError("No null terminator found for FullName in record_data.")

        full_name_bytes = record_data[:null_pos]
        body_bytes = record_data[null_pos + 1 :]

        full_name = full_name_bytes.decode('utf-8', errors='replace')

        records.append({
            'record_length': record_size,  
            'full_name': full_name,
            'body': body_bytes
        })

    if offset + 4 <= length:
        closing_magic = memory_blocks[offset : offset + 4]
        if closing_magic != MAGIC:
            raise ValueError("No closing MAGIC at the end of data.")
        offset += 4

    return records

def download(dev,address,size, output_folder):
    # Create the output folder if it doesn't exist
    os.makedirs(output_folder, exist_ok=True)

    memory_blocks = dump_scripts(dev,address,size)
    print(f"Size: {len(memory_blocks)} bytes")

    records = parse_memory_blocks(memory_blocks)
    print(f"Found {len(records)} records.")

    for record in records:
        if record["full_name"] == "PADDING":
            print(f"Skipping PADDING record. Length: {record['record_length']}")
            continue

        filename = record["full_name"]
        body = record["body"]


        if filename.lower().endswith(".py"):
            # Remove leading 0x01 if present
            if body and body[0] == 0x01:
                body = body[1:]
            # Remove trailing 0x00 if present
            if body and body[-1] == 0x00:
                body = body[:-1]

        file_path = os.path.join(output_folder, filename)
        with open(file_path, "wb") as f:
            f.write(body)
        
        print(f"Wrote file: {file_path} ({len(body)} bytes)")




def send_scripts(dev,start_addr, blob, addr_step=0x800, chunk_size=2048):

    print("[send_scripts] Waiting for device to become dfuIDLE or dfuERROR...")
    wait_for_idle_or_error(dev)

    total_size = len(blob)
    num_chunks = math.ceil(total_size / chunk_size)
    current_addr = start_addr + 0x4 # we don't want to overwrite the MAGIC
    offset = 0

    for chunk_idx in range(num_chunks):
        chunk = blob[offset : offset + chunk_size]
        set_address_pointer(dev,current_addr)
        wait_for_status(dev)
        dfu_download_and_wait_idle(dev, block_num=2, data=chunk)
        offset += len(chunk)
        current_addr += addr_step

    dfu_abort(dev)
    wait_for_idle_or_error(dev)


def upload(dev,start_addr,size, folder):
    FINAL_SIZE = size

    file_list = [
        f for f in os.listdir(folder)
        if os.path.isfile(os.path.join(folder, f))
    ]

    first = "pr.sys"
    second = "gp.sys"

    ordered_file_list = []

    if first in file_list:
        ordered_file_list.append(first)
        file_list.remove(first)

    if second in file_list:
        ordered_file_list.append(second)
        file_list.remove(second)

    ordered_file_list.extend(file_list)
    blob = bytearray()

    for filename in ordered_file_list:
        file_path = os.path.join(folder, filename)
        with open(file_path, 'rb') as fp:
            body = fp.read()
        filename_bytes = filename.encode('utf-8', errors='replace') + b'\x00'

        if filename.lower().endswith(".py"):
            body = b'\x01' + body + b'\x00'

        record_size = 2 + len(filename_bytes) + len(body)
        blob += struct.pack('<H', record_size)
        blob += filename_bytes
        blob += body

    current_size = len(blob)
    needed_padding = FINAL_SIZE - current_size
    blob += b'\x00' * needed_padding
    blob = bytes(blob)
    send_scripts(dev,start_addr, blob)

    print(f"[upload] Successfully built {len(blob)}-byte blob and called send_scripts().")



def read_global_preferences(filename):
    with open(filename, "rb") as f:
        data = f.read()
        if len(data) != 9:
            raise ValueError(
                f"File must be exactly 9 bytes (got {len(data)} bytes)."
            )

    m_version = data[0]
    # 4-byte little-endian integer (signed)
    m_brightnessLevel = int.from_bytes(data[1:5], byteorder='little', signed=True)

    m_language = data[5]   # enum, stored as 1 byte
    m_country = data[6]    # enum, stored as 1 byte
    m_showPopUp = bool(data[7])  # convert from 0/1 => False/True
    m_font = data[8]       # enum, stored as 1 byte

    prefs_dict = {
        "version": m_version,
        "brightnessLevel": m_brightnessLevel,
        "language": m_language,
        "country": m_country,
        "showPopUp": m_showPopUp,
        "font": m_font,
    }

    return prefs_dict


def write_global_preferences(prefs_dict, filename):

    version = prefs_dict["version"] & 0xFF
    brightness_level = prefs_dict["brightnessLevel"]  # This is a signed int
    language = prefs_dict["language"] & 0xFF
    country = prefs_dict["country"] & 0xFF
    show_pop_up = 1 if prefs_dict["showPopUp"] else 0
    font = prefs_dict["font"] & 0xFF

    data = bytearray(9)
    data[0] = version
    data[1:5] = brightness_level.to_bytes(4, byteorder='little', signed=True)
    data[5] = language
    data[6] = country
    data[7] = show_pop_up
    data[8] = font

    with open(filename, "wb") as f:
        f.write(data)


def parse_calculation_preferences(byte0, byte1):

    angleUnit          =  (byte0 >> 0) & 0b11
    displayMode        =  (byte0 >> 2) & 0b11
    editionMode        =  (byte0 >> 4) & 0b1
    complexFormat      =  (byte0 >> 5) & 0b11
    padding            =  (byte0 >> 7) & 0b1
    numberOfSignDigits =  byte1

    return {
        "angleUnit": angleUnit,
        "displayMode": displayMode,
        "editionMode": editionMode,
        "complexFormat": complexFormat,
        "padding": padding,
        "numberOfSignificantDigits": numberOfSignDigits,
    }


def build_calculation_preferences_bytes(calc_pref_dict):

    angleUnit = calc_pref_dict["angleUnit"] & 0b11
    displayMode = calc_pref_dict["displayMode"] & 0b11
    editionMode = calc_pref_dict["editionMode"] & 0b1
    complexFormat = calc_pref_dict["complexFormat"] & 0b11
    padding = calc_pref_dict["padding"] & 0b1
    numberOfSignificantDigits = calc_pref_dict["numberOfSignificantDigits"] & 0xFF

    byte0 = (angleUnit
            | (displayMode << 2)
            | (editionMode << 4)
            | (complexFormat << 5)
            | (padding << 7))
    
    byte1 = numberOfSignificantDigits

    return byte0, byte1


def read_preferences(filename):

    with open(filename, "rb") as f:
        data = f.read()
        if len(data) != 11:
            raise ValueError(
                f"File must be exactly 11 bytes (got {len(data)} bytes)."
            )
    
    m_version = data[0]
    

    calc_pref_byte0 = data[1]
    calc_pref_byte1 = data[2]
    calculation_preferences = parse_calculation_preferences(calc_pref_byte0, calc_pref_byte1)
    
    m_examMode = int.from_bytes(data[3:5], byteorder='little', signed=False)
    
    m_forceExamModeReload = bool(data[5])
    m_combinatoricSymbols = data[6]  # enum
    m_mixedFractions      = bool(data[7])
    m_logarithmBasePos    = data[8]  # enum
    m_logarithmKeyEvent   = data[9]  # enum
    m_parabolaParameter   = data[10] # enum
    
    # Build a dictionary
    prefs_dict = {
        "version": m_version,
        "calculationPreferences": calculation_preferences,
        "examMode": m_examMode,
        "forceExamModeReload": m_forceExamModeReload,
        "combinatoricSymbols": m_combinatoricSymbols,
        "mixedFractionsAreEnabled": m_mixedFractions,
        "logarithmBasePosition": m_logarithmBasePos,
        "logarithmKeyEvent": m_logarithmKeyEvent,
        "parabolaParameter": m_parabolaParameter,
    }
    
    return prefs_dict


def write_preferences(prefs_dict, filename):
    version = prefs_dict["version"] & 0xFF

    # Convert the calculationPreferences dictionary back into two bytes
    calc_pref_dict = prefs_dict["calculationPreferences"]
    calc_byte0, calc_byte1 = build_calculation_preferences_bytes(calc_pref_dict)

    # examMode is a 2-byte enum (unsigned short)
    exam_mode = prefs_dict["examMode"] & 0xFFFF
    
    force_exam_mode_reload = 1 if prefs_dict["forceExamModeReload"] else 0
    combinatoric_symbols = prefs_dict["combinatoricSymbols"] & 0xFF
    mixed_fractions = 1 if prefs_dict["mixedFractionsAreEnabled"] else 0
    logarithm_base_pos = prefs_dict["logarithmBasePosition"] & 0xFF
    logarithm_key_event = prefs_dict["logarithmKeyEvent"] & 0xFF
    parabola_parameter = prefs_dict["parabolaParameter"] & 0xFF

    # Build 11 bytes
    data = bytearray(11)
    data[0] = version
    data[1] = calc_byte0
    data[2] = calc_byte1
    data[3:5] = exam_mode.to_bytes(2, byteorder='little', signed=False)
    data[5] = force_exam_mode_reload
    data[6] = combinatoric_symbols
    data[7] = mixed_fractions
    data[8] = logarithm_base_pos
    data[9] = logarithm_key_event
    data[10] = parabola_parameter

    # Write it to disk
    with open(filename, "wb") as f:
        f.write(data)