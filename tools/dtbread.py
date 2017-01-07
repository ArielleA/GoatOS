#! /usr/bin/env python3

import struct,sys
from termcolor import colored

class FDTHeader:
    # Simple class for processing the FDT Header
    #
    # Usage: instansiate class with raw string of FDT object.
    # Verification and unpacking will occur in the init function.
    # Helper functions are provided for each of the elements.

    def process_from_string(self,string):

        tempval = struct.unpack_from('!IIIIIIIIIII',string)
        
        #Validate header where possible
        if tempval[0] != 0xd00dfeed:
            raise ValueError('DTB Magic Value not found')
        if self.version not in [16,17]:
            raise ValueError('DTB version is not supported. Must be 16 or 17.')
        
        #Validation okay, set values
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
        return struct.pack('!IIIIIIIIIII',
	    self.magic,
	    self.totalsize,
	    self.off_dt_struct,
	    self.off_dt_strings,
	    self.off_mem_rsvmap,
	    self.version,
	    self.last_comp_version,
	    self.size_dt_strings,
	    self.size_dt_struct)
        
def read_dtb_header(string):
    #Read the DTB header structure and return it as a tuple
    return struct.unpack_from('!IIIIIIIIIII',string)

def read_memory_reservations(string,offset):
    reservations = []
    while 1:
        item = struct.unpack_from('!II',string, offset=offset)
        offset = offset + struct.calcsize('!II')
        #print(item)
        if item == (0,0):
            break
        reservations.append(item)
    return reservations

def read_string_block(string,offset,length):
    strings = {}
    string_offset = 0
    while string_offset < length:
        curpos = offset+string_offset
        index = string[curpos:].find(b'\0')
        item = string[curpos:curpos+index]
        strings[string_offset]=item
        #print (string_offset,item)
        string_offset = string_offset+index+1
    return strings

def calc_length_word_align(length):
    words = int(length/4)
    rem = length%4
    if rem > 0:
        words = words + 1
    return words*4

def read_struct_block(string,offset,length,properties):
    string = string[offset:]
    nodes = {}
    curnode_num = -1
    node_stack = []
    nodes_total = -1
    string_offset = 0
    while string_offset < length:
        cmd = struct.unpack_from('!I',string,offset=string_offset)[0]
        string_offset=string_offset+struct.calcsize('!I')
        if cmd == 1:
            node_stack.append(curnode_num)
            nodes_total = nodes_total + 1
            nodes[nodes_total] = {}
            nodes[nodes_total]['parent']=curnode_num
            curnode_num = nodes_total
            #node = process_node(string,curpos,offset+length-curpos,strings)
            nameidx = string [ string_offset : ].find(b'\0')
            name = string [ string_offset : string_offset+nameidx ]
            nodes[curnode_num]['name']=name
            print ("Found CMD",cmd,"with name",name,"at position",string_offset,"continuing from",end=' ')
            string_offset=string_offset+calc_length_word_align(nameidx+1)
            print (string_offset)
        elif cmd == 3:
            property_len, property_nameoff = struct.unpack_from('!II',string, offset=string_offset)
            string_offset=string_offset+struct.calcsize('!II')
            property_name = properties[property_nameoff]
            print (property_len,property_name)
            property_val = string[string_offset:string_offset+property_len]
            string_offset=string_offset+calc_length_word_align(property_len)
            nodes[curnode_num][property_name]=property_val
            print ("Found CMD",cmd,"with property name",property_name,"and value",property_val,"continuing from",string_offset)
        elif cmd == 2:
            print ("Found CMD",cmd,"finishing node",curnode_num,"returning to node",end=' ')
            curnode_num=node_stack.pop()
            print (curnode_num)
        elif cmd == 4:
            print ("Found CMD",cmd,"which is a NOP, ignoring")
        else:
            print("Unknown Command",cmd)  
            print (nodes)
            break
        


if __name__ == '__main__':
   a = open('xenvm-4.2.dtb','rb').read()
   header = FDTHeader()
   header.process_from_string(a)

   #print "Raw Header Tuple",header
   print ("Hex of Magic Value:",colored(format(header.magic,'x'),'blue'))
   if header.magic == 0xd00dfeed:
        print (colored("Header:",'cyan'),colored("Valid DTB magic value found",'green',attrs=['bold']))
        print (colored("Header",'cyan'),"-> Total Size of file:     ",colored('{0:>8d} {0:>#8x}'.format(header.totalsize),'yellow'))
        print (colored("Header",'cyan'),"-> Offset to Struct Block: ",colored('{0:>8d} {0:>#8x}'.format(header.off_dt_struct),'yellow')," with size: ",colored('{0:>8d} {0:>#8x}'.format(header.size_dt_struct),'yellow'))
        print (colored("Header",'cyan'),"-> Offset to String Block: ",colored('{0:>8d} {0:>#8x}'.format(header.off_dt_strings),'yellow')," with size: ",colored('{0:>8d} {0:>#8x}'.format(header.size_dt_strings),'yellow'))
        print (colored("Header",'cyan'),"-> Offset to Memory Reser: ",colored('{0:>8d} {0:>#8x}'.format(header.off_mem_rsvmap),'yellow'))
        print (colored("Header",'cyan'),"-> Version of DTB:         ",colored('{0:>8d} {0:>#8x}'.format(header.version),'yellow'))
        print (colored("Header",'cyan'),"-> Previous Version of DTB:",colored('{0:>8d} {0:>#8x}'.format(header.last_comp_version),'yellow'))
        print (colored("Header",'cyan'),"-> Boot CPU Number:        ",colored('{0:>8d} {0:>#8x}'.format(header.boot_cpuid_phys),'yellow'))
        print
        b = read_memory_reservations(a,header.off_mem_rsvmap)
        if b == []:
            print (colored("Reservations",'cyan'),'-> There are no memory reservations')
        else:
           for each in b:
               print (colored("Reservations",'cyan'),'-> Memory Reservation at: ',colored('{0:>#8x}'.format(each[0]))," for size: ",colored('{0:>#8x}'.format(each[1])))
        c = read_string_block(a,header.off_dt_strings,header.size_dt_strings)
        print (c)
        d = read_struct_block(a,header.off_dt_struct,header.size_dt_struct,c)
   else:
        print (coloured("Magic value not found. Aborted!"),'red',attrs=['bold'])
        sys.exit(1)
