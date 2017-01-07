#! /usr/bin/env python3

import struct,sys
from termcolor import colored

class DTBHeader:
    # Simple class for processing the DTB Header
    #
    # Usage: instansiate class with raw string of DTB object.
    # Verification and unpacking will occur in the init function.
    # Helper functions are provided for each of the elements.

    def process_string(self,string):

        tempval = struct.unpack_from('!IIIIIIIIIII',string)
        self.header['magic'] = tempval[0]
        if self.magic != 0xd00dfeed:
            raise ValueError('DTB Magic Value not found')

    def __init__(self):
        self.header = {
		'magic':0xd00dfeed,
                'totalsize':0,
                'offset_dt_stuct':0,
                'offset_dt_strings':0,
                'offset_mem_rsvmap':0,
                'version':17,
                'last_comp_version':16,
		'boot_cpuid_phys':0,
		'size_dt_strings':0,
		'size_dt_struct':0 }
        
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
   header = read_dtb_header(a)

   #print "Raw Header Tuple",header
   print ("Hex of Magic Value:",colored(format(header[0],'x'),'blue'))
   if header[0] == 0xd00dfeed:
        print (colored("Header:",'cyan'),colored("Valid DTB magic value found",'green',attrs=['bold']))
        print (colored("Header",'cyan'),"-> Total Size of file:     ",colored('{0:>8d} {0:>#8x}'.format(header[1]),'yellow'))
        print (colored("Header",'cyan'),"-> Offset to Struct Block: ",colored('{0:>8d} {0:>#8x}'.format(header[2]),'yellow')," with size: ",colored('{0:>8d} {0:>#8x}'.format(header[9]),'yellow'))
        print (colored("Header",'cyan'),"-> Offset to String Block: ",colored('{0:>8d} {0:>#8x}'.format(header[3]),'yellow')," with size: ",colored('{0:>8d} {0:>#8x}'.format(header[8]),'yellow'))
        print (colored("Header",'cyan'),"-> Offset to Memory Reser: ",colored('{0:>8d} {0:>#8x}'.format(header[4]),'yellow'))
        print (colored("Header",'cyan'),"-> Version of DTB:         ",colored('{0:>8d} {0:>#8x}'.format(header[5]),'yellow'))
        print (colored("Header",'cyan'),"-> Previous Version of DTB:",colored('{0:>8d} {0:>#8x}'.format(header[6]),'yellow'))
        print (colored("Header",'cyan'),"-> Boot CPU Number:        ",colored('{0:>8d} {0:>#8x}'.format(header[7]),'yellow'))
        print
        b = read_memory_reservations(a,header[4])
        if b == []:
            print (colored("Reservations",'cyan'),'-> There are no memory reservations')
        else:
           for each in b:
               print (colored("Reservations",'cyan'),'-> Memory Reservation at: ',colored('{0:>#8x}'.format(each[0]))," for size: ",colored('{0:>#8x}'.format(each[1])))
        c = read_string_block(a,header[3],header[8])
        print (c)
        d = read_struct_block(a,header[2],header[9],c)
   else:
        print (coloured("Magic value not found. Aborted!"),'red',attrs=['bold'])
        sys.exit(1)
