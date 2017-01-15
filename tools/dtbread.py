#! /usr/bin/env python3
# -*- coding: utf-8 _*_

"""Functions and classes for reading a Flattened Device Tree"""

import struct
import sys
from termcolor import colored


class FDTHeader:
    """Simple class for processing the FDT Header

    Usage: instansiate class with raw string of FDT object.
    Verification and unpacking will occur in the init function.
    Helper functions are provided for each of the elements."""

    def process_from_string(self, string):
        """Read the header from a string object"""
        tempval = struct.unpack_from('!IIIIIIIIIII', string)

        # Validate header where possible
        if tempval[0] != 0xd00dfeed:
            raise ValueError('DTB Magic Value not found')
        if tempval[5] not in [16, 17]:
            raise ValueError('DTB version is not supported. Must be 16 or 17.')

        # Validation okay, set values
        self.magic = tempval[0]
        self.totalsize = tempval[1]
        self.off_dt_struct = tempval[2]
        self.off_dt_strings = tempval[3]
        self.off_mem_rsvmap = tempval[4]
        self.version = tempval[5]
        self.last_comp_version = tempval[6]
        self.boot_cpuid_phys = tempval[7]
        self.size_dt_strings = tempval[8]
        self.size_dt_struct = tempval[9]

    def __init__(self):
        self.magic = 0xd00dfeed
        self.totalsize = 0
        self.off_dt_struct = 0
        self.off_dt_strings = 0
        self.off_mem_rsvmap = 0
        self.version = 17
        self.last_comp_version = 16
        self.boot_cpuid_phys = 0
        self.size_dt_strings = 0
        self.size_dt_struct = 0

    def str(self):
        """Return the header as a string"""
        return struct.pack(
            '!IIIIIIIIIII',
            self.magic,
            self.totalsize,
            self.off_dt_struct,
            self.off_dt_strings,
            self.off_mem_rsvmap,
            self.version,
            self.last_comp_version,
            self.size_dt_strings,
            self.size_dt_struct
        )


class FDTStrings:
    """The class that unpacks the String section of FDT File"""
    def __init__(self):
        self.originstring = b''
        self.stringlength = 0
        self.stringdict = {}

    def set_raw_string(self, string, length):
        """This function loads the raw string for this class instance."""
        if len(string) != length:
            raise ValueError('Length of passed string does not match length')
        self.originstring = string
        self.stringlength = length

    def __getitem__(self, key):
        if key in self.stringdict:
            return self.stringdict[key]
        else:
            if key < self.stringlength:
                index = self.originstring[key:].find(b'\0')
                item = self.originstring[key:key + index]
                self.stringdict[key] = item
                return item
            else:
                raise IndexError


class FDTNode:
    """Class for managing nodes within the Structure section of a FDT"""
    def __init__(self, name):
        self.name = name
        self.children = []
        self.properties = {}
        self.parent = None

    def set_parent(self, parent):
        """Set the link to parent object"""
        self.parent = parent

    def add_child(self, location):
        """Add a child vertex"""
        self.children.append(location)

    def get_children(self):
        """Return the child vertices"""
        return self.children

    def add_property(self, name, value=None):
        """Add a property to the current node"""
        # This code needs improvement, some grammar input mechanism is required.
        if b'#' in name:
            value = struct.unpack('!I', value)[0]
        elif name in [b'phandle', b'virtual-reg']:
            value = struct.unpack('!I', value)[0]
        elif name in [b'compatible', b'status']:
            value = value.strip(b'\x00').decode('utf-8')
            value = value.split('\x00')
        elif name in [b'device_type', b'method', b'bootargs', b'model', b'label']:
            value = value.strip(b'\x00').decode('utf-8')
        elif name in [b'reg']:
            value = self.process_reg(self.get_reg_size(), value)
        self.properties[name.decode('utf-8')] = value

    def get_properties(self):
        """Return the properties attached to the node"""
        return self.properties

    def get_reg_size(self):
        """Get the size of the cells for a reg field. Or if not found return default"""
        if '#address-cells' in self.properties and '#size-cells' in self.properties:
            return self.properties['#address-cells'], self.properties['#size-cells']
        elif self.parent is None:
            return 2, 1
        else:
            return self.parent.get_reg_size()

    @staticmethod
    def get_value(reg, size):
        """Return the value based on size of field in cells"""
        if size == 0:
            return 0, 0
        elif size == 1:
            size = struct.calcsize('!I')
            value = struct.unpack('!I', reg[:size])[0]
            return value, size
        elif size == 2:
            size = struct.calcsize('!Q')
            value = struct.unpack('!Q', reg[:size])[0]
            return value, size
        else:
            raise ValueError("Register size is too large")

    def process_reg(self, reg_size, reg):
        """Process a reg field"""
        register_list = []
        while reg != b'':
            ac, acs = self.get_value(reg, reg_size[0])
            reg = reg[acs:]
            sc, scs = self.get_value(reg, reg_size[1])
            reg = reg[scs:]
            register_list.append((ac, sc))
        return register_list

    def __getitem__(self, key):
        return self.properties[key]

    def keys(self):
        """Return list of properties"""
        return self.properties.keys()

    def get_name(self):
        """Get the node's name"""
        return self.name


class FDTStruct:
    """FDT Graph Structure Class"""
    CMD_Node_Start = 1
    CMD_Node_End = 2
    CMD_Property = 3
    CMD_NoOperation = 4
    CMD_Stream_End = 9

    def __init__(self, string, length, properties):
        self.string = string
        self.length = length
        self.properties = properties
        self.nodes = {}
        self.root = 0

    def get_command(self, offset):
        """Unpack command from stream"""
        cmd = struct.unpack_from('!I', self.string, offset=offset)[0]
        # if cmd not in [1,2,3,4,9]:
        #    raise ValueError('Command not recognised')
        offset += struct.calcsize('!I')
        return cmd, offset

    def get_root_node(self):
        """Return the root node"""
        return self.root

    def __getitem__(self, key):
        return self.nodes[key]

    def new_node(self, location, offset):
        """Process creation of new node."""
        # First we get the name of the node
        nameidx = self.string[offset:].find(b'\0')
        name = self.string[offset: offset + nameidx]
        string_offset = offset + calc_length_word_align(nameidx + 1)
        node = FDTNode(name)
        self.nodes[location] = node
        return string_offset

    def new_property(self, node, offset, properties):
        """Add a property to the specified node"""
        # Does this need refactoring to pass in the node object?
        property_len, property_nameoff = struct.unpack_from('!II', self.string, offset=offset)
        offset += struct.calcsize('!II')
        property_name = properties[property_nameoff]
        property_val = self.string[offset:offset + property_len]
        offset += calc_length_word_align(property_len)
        self.nodes[node].add_property(property_name, property_val)
        return offset

    def process_struct(self):
        """The main structure processing method

        This node manages the dispatch of all the sub-commands"""
        offset = 0
        current_node = 0
        stack = []
        print(stack, current_node)
        while offset < self.length:
            cmd, next_offset = self.get_command(offset)
            # Process Commands
            if cmd == self.CMD_Node_Start:
                # Check if we are root, if not append on stack
                if offset != 0:
                    stack.append(current_node)
                # Create new node and return next offset
                next_offset = self.new_node(offset, next_offset)
                # If we are the root node, do not add link to self
                if offset != 0:
                    self.nodes[current_node].add_child(offset)
                    self.nodes[offset].set_parent(self.nodes[current_node])
                # Make our self be the current node
                current_node = offset
            elif cmd == self.CMD_Node_End:
                if stack != []:
                    current_node = stack.pop()
            elif cmd == self.CMD_Property:
                next_offset = self.new_property(current_node, next_offset, self.properties)
            elif cmd == self.CMD_Stream_End:
                break
            offset = next_offset


def read_memory_reservations(string, offset):
    """Read memory reservations"""
    reservations = []
    while 1:
        item = struct.unpack_from('!II', string, offset=offset)
        offset += struct.calcsize('!II')
        if item == (0, 0):
            break
        reservations.append(item)
    return reservations


def calc_length_word_align(length):
    """Calculation of length to word aligned string"""
    words = int(length / 4)
    rem = length % 4
    if rem > 0:
        words += 1
    return words * 4


def debug_info_header(header):
    """Pretty print the header"""
    print(colored("Header:", 'cyan'), colored("Valid FDT magic value found", "green", attrs=['bold']))
    print(colored("Header", 'cyan'), "-> Total Size of file:     ",
          colored('{0:>8d} {0:>#8x}'.format(header.totalsize), 'yellow'))
    print(colored("Header", 'cyan'), "-> Offset to Struct Block: ",
          colored('{0:>8d} {0:>#8x}'.format(header.off_dt_struct), 'yellow'), " with size: ",
          colored('{0:>8d} {0:>#8x}'.format(header.size_dt_struct), 'yellow'))
    print(colored("Header", 'cyan'), "-> Offset to String Block: ",
          colored('{0:>8d} {0:>#8x}'.format(header.off_dt_strings), 'yellow'), " with size: ",
          colored('{0:>8d} {0:>#8x}'.format(header.size_dt_strings), 'yellow'))
    print(colored("Header", 'cyan'), "-> Offset to Memory Reser: ",
          colored('{0:>8d} {0:>#8x}'.format(header.off_mem_rsvmap), 'yellow'))
    print(colored("Header", 'cyan'), "-> Version of DTB:         ",
          colored('{0:>8d} {0:>#8x}'.format(header.version), 'yellow'))
    print(colored("Header", 'cyan'), "-> Previous Version of DTB:",
          colored('{0:>8d} {0:>#8x}'.format(header.last_comp_version), 'yellow'))
    print(colored("Header", 'cyan'), "-> Boot CPU Number:        ",
          colored('{0:>8d} {0:>#8x}'.format(header.boot_cpuid_phys), 'yellow'))
    print()


def debug_node(fdt, node, depth, path):
    """Pretty print the provided node"""
    depth += 1
    path = path + fdt[node].get_name() + b'/'
    print(colored("Node:", 'cyan'), "-> ", colored(path.decode('ascii'), 'green'), '{')
    for key in fdt[node].keys():
        print(colored("Node:", 'cyan'), "-> ", "   " * depth, key, "=", colored(fdt[node][key], 'yellow'))
    for leaf in fdt[node].get_children():
        debug_node(fdt, leaf, depth, path)
    print(colored("Node:", 'cyan'), "-> ", "   " * depth, "};")


def debug_info_struct(fdt):
    """Pretty print the FDT structure"""
    # Traverse node tree in depth first
    depth = 0
    path = b''
    root = fdt.get_root_node()
    debug_node(fdt, root, depth, path)


if __name__ == '__main__':
    a = open(sys.argv[1], 'rb').read()
    fdtheader = FDTHeader()
    fdtheader.process_from_string(a)

    # print "Raw Header Tuple",header
    # print ("Hex of Magic Value:",colored(format(header.magic,'x'),'blue'))
    if fdtheader.magic == 0xd00dfeed:
        debug_info_header(fdtheader)
        memory_reservations = read_memory_reservations(a, fdtheader.off_mem_rsvmap)
        if memory_reservations is []:
            print(colored("Reservations", 'cyan'), '-> There are no memory reservations')
        else:
            for each in memory_reservations:
                print(
                    colored("Reservations", 'cyan'), '-> Memory Reservation at: ', colored('{0:>#8x}'.format(each[0])),
                    " for size: ", colored('{0:>#8x}'.format(each[1])))
        # c = read_string_block(a,header.off_dt_strings,header.size_dt_strings)
        fdt_strings = FDTStrings()
        fdt_strings.set_raw_string(a[fdtheader.off_dt_strings:fdtheader.off_dt_strings + fdtheader.size_dt_strings],
                                   fdtheader.size_dt_strings)
        ftd_struct = FDTStruct(a[fdtheader.off_dt_struct:], fdtheader.size_dt_struct, fdt_strings)
        ftd_struct.process_struct()
        debug_info_struct(ftd_struct)
        # d = read_struct_block(a,header.off_dt_struct,header.size_dt_struct,c)
    else:
        print(colored("Magic value not found. Aborted!", 'red', attrs=['bold']))
        sys.exit(1)
