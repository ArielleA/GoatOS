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

class FDTStrings:
    def __init__(self):
        self.originstring = b''
        self.stringlength = 0
        self.stringdict = {}

    def set_raw_string(self,string,length):
        #This function loads the raw string for this class instance.
        if len(string) != length:
            raise ValueError('Length of passed string does not match length')
        self.originstring = string
        self.stringlength = length
 
    def __getitem__(self,key):
        if key in self.stringdict:
            return self.stringdict[key]
        else:
            if key < self.stringlength:
                index=self.originstring[key:].find(b'\0')
                item=self.originstring[key:key+index]
                self.stringdict[key]=item
                return item
            else:
                raise IndexError

class FDTNode:
    def __init__(self,name):
        self.name = name
        self.children = []
        self.properties = {}
        self.parent = None

    def set_parent(self,parent):
        self.parent=parent
   
    def add_child(self,location):
        self.children.append(location)

    def get_children(self):
        return self.children

    def add_property(self, name, value=None):
        #This code needs improvement, some grammar input mechanism is required.
        if b'#' in name:
            value = struct.unpack('!I',value)[0]
        elif name in [b'phandle',b'virtual-reg']:
            value = struct.unpack('!I',value)[0]
        elif name in [b'compatible',b'status']:
            value = value.strip(b'\x00').decode('utf-8')
            value = value.split('\x00')
        elif name in [b'device_type',b'method',b'bootargs',b'model',b'label']:
            value = value.strip(b'\x00').decode('utf-8')
        elif name in [b'reg']:
            print(self.parent,self.properties)
            value = self.process_reg(self.get_reg_size(),value)
        self.properties[name.decode('utf-8')]=value

    def get_properties(self):
        return self.properties
    
    def get_reg_size(self):
        print(self.parent, self.properties)
        if '#address-cells' in self.properties and '#size-cells' in self.properties:
            return (self.properties['#address-cells'],self.properties['#size-cells'])
        elif self.parent == None:
            return (2,1)
        else:
            return self.parent.get_reg_size()

    def get_0(self,reg):
        return (0,0)

    def get_1(self,reg):
        size = struct.calcsize('!I')
        value = struct.unpack('!I',reg[:size])[0]
        return (value,size)
      
    def get_2(self,reg):
        size = struct.calcsize('!Q')
        value = struct.unpack('!Q',reg[:size])[0]
        return (value,size)

    def get_value(self,reg,size):
        if size == 0:
            return self.get_0(reg)
        elif size == 1:
            return self.get_1(reg)
        elif size == 2:
            return self.get_2(reg)
        else:
            raise ValueError("Register size is too large")


    def process_reg(self,reg_size,reg):
        
        register_list = []
        while reg != b'':

            print(reg_size,reg,len(reg))
            ac, acs = self.get_value(reg,reg_size[0])
            reg = reg[acs:]
            sc, scs = self.get_value(reg,reg_size[1])
            reg = reg[scs:]
            register_list.append((ac,sc))
        return register_list


    
    def __getitem__(self,key):
        return self.properties[key]

    def keys(self):
        return self.properties.keys()

    def get_name(self):
        return self.name

class FDTStruct:
    def __init__(self, string, length, properties):
        self.string = string
        self.length = length
        self.properties = properties
        self.nodes = {}
        self.root = 0

    def get_command(self,offset):
        cmd = struct.unpack_from('!I',self.string,offset=offset)[0]
        #if cmd not in [1,2,3,4,9]:
        #    raise ValueError('Command not recognised')
        offset=offset+struct.calcsize('!I')
        return (cmd,offset)

    def get_root_node(self):
        return self.root   

    def __getitem__(self, key):
        return self.nodes[key]

    def new_node(self,location, offset):
        #First we get the name of the node
        nameidx = self.string [ offset : ].find(b'\0')
        name = self.string [ offset : offset + nameidx ]
        string_offset=offset+calc_length_word_align(nameidx+1)
        node = FDTNode(name)
        self.nodes[location] = node
        return string_offset 

    def new_property(self,curnode,offset,properties):
        property_len, property_nameoff = struct.unpack_from('!II',self.string, offset=offset)
        offset=offset+struct.calcsize('!II')
        property_name = properties[property_nameoff]
        property_val = self.string[offset:offset+property_len]
        offset=offset+calc_length_word_align(property_len)
        self.nodes[curnode].add_property(property_name,property_val)
        return offset

    def process_struct(self):
        offset = 0
        curnode = 0
        stack = []
        while offset < self.length:
            cmd,next_offset = self.get_command(offset)
            #Process Commands
            if cmd == 1:
                #Check if we are root, if not append on stack
                if offset != 0:
                   stack.append(curnode)
                #Create new node and return next offset
                next_offset = self.new_node(offset,next_offset)
                #If we are the root node, do not add link to self
                if offset != 0:
                    self.nodes[curnode].add_child(offset)
                    self.nodes[offset].set_parent(self.nodes[curnode])
                #Make ourself be the current node
                curnode = offset
            elif cmd == 2:
                if stack != []: 
                    curnode = stack.pop()
            elif cmd == 3:
                next_offset = self.new_property(curnode,next_offset,self.properties)
            elif cmd == 9:
                break;
            offset = next_offset


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

def calc_length_word_align(length):
    words = int(length/4)
    rem = length%4
    if rem > 0:
        words = words + 1
    return words*4

        
def debug_info_header(header):
   print (colored("Header:",'cyan'),colored("Valid FDT magic value found",'green',attrs=['bold']))
   print (colored("Header",'cyan'),"-> Total Size of file:     ",colored('{0:>8d} {0:>#8x}'.format(header.totalsize),'yellow'))
   print (colored("Header",'cyan'),"-> Offset to Struct Block: ",colored('{0:>8d} {0:>#8x}'.format(header.off_dt_struct),'yellow')," with size: ",colored('{0:>8d} {0:>#8x}'.format(header.size_dt_struct),'yellow'))
   print (colored("Header",'cyan'),"-> Offset to String Block: ",colored('{0:>8d} {0:>#8x}'.format(header.off_dt_strings),'yellow')," with size: ",colored('{0:>8d} {0:>#8x}'.format(header.size_dt_strings),'yellow'))
   print (colored("Header",'cyan'),"-> Offset to Memory Reser: ",colored('{0:>8d} {0:>#8x}'.format(header.off_mem_rsvmap),'yellow'))
   print (colored("Header",'cyan'),"-> Version of DTB:         ",colored('{0:>8d} {0:>#8x}'.format(header.version),'yellow'))
   print (colored("Header",'cyan'),"-> Previous Version of DTB:",colored('{0:>8d} {0:>#8x}'.format(header.last_comp_version),'yellow'))
   print (colored("Header",'cyan'),"-> Boot CPU Number:        ",colored('{0:>8d} {0:>#8x}'.format(header.boot_cpuid_phys),'yellow'))
   print

def debug_node(fdt,node,depth,path):
   depth=depth+1
   path=path+fdt[node].get_name()+b'/'
   print (colored("Node:",'cyan'),"-> ",colored(path.decode('ascii'),'green'),'{')
   for each in fdt[node].keys():
       print (colored("Node:",'cyan'),"-> ","   "*depth,each,"=",colored(fdt[node][each],'yellow'))
   for each in fdt[node].get_children():
       debug_node(fdt,each,depth,path)
   print (colored("Node:",'cyan'),"-> ","   "*depth,"};")

def debug_info_struct(fdt):
   #Traverse node tree in depth first
   depth = 0
   path = b''
   root=fdt.get_root_node()
   debug_node(fdt,root,depth,path)
   
if __name__ == '__main__':
   a = open(sys.argv[1],'rb').read()
   header = FDTHeader()
   header.process_from_string(a)

   #print "Raw Header Tuple",header
   #print ("Hex of Magic Value:",colored(format(header.magic,'x'),'blue'))
   if header.magic == 0xd00dfeed:
      debug_info_header(header)
      b = read_memory_reservations(a,header.off_mem_rsvmap)
      if b == []:
          print (colored("Reservations",'cyan'),'-> There are no memory reservations')
      else:
          for each in b:
              print (colored("Reservations",'cyan'),'-> Memory Reservation at: ',colored('{0:>#8x}'.format(each[0]))," for size: ",colored('{0:>#8x}'.format(each[1])))
      #c = read_string_block(a,header.off_dt_strings,header.size_dt_strings)
      c = FDTStrings()
      c.set_raw_string(a[header.off_dt_strings:header.off_dt_strings+header.size_dt_strings],header.size_dt_strings)
      d = FDTStruct(a[header.off_dt_struct:],header.size_dt_struct,c)
      d.process_struct()
      debug_info_struct(d)
      #d = read_struct_block(a,header.off_dt_struct,header.size_dt_struct,c)
   else:
        print (coloured("Magic value not found. Aborted!"),'red',attrs=['bold'])
        sys.exit(1)
