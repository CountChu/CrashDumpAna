#
# FILENAME.
#       crash_dump_ana.py - Crash Dump Analyzer Python Application.
#
# FUNCTIONAL DESCRIPTION.
#       The application analyzes crash dump.
#
# NOTICE.
#       Author: visualge@gmail.com (CountChu)
#       Created on 2024/1/20
#       Updated on 2024/6/2
#

#
# Common packages.
#

import argparse
import os
import sys
import re

#
# For Debugging.
#

import pdb 
br = pdb.set_trace						# br: break down
lg = print								# lg: log


def build_args():
    desc = '''
Usage 1: Analyze crash dump.
	python crash_dump_ana.py crash-dump-1.txt

Usage 2: Analyze crash dump with an EFI. 
	python crash_dump_ana.py crash-dump-2.txt -i bootx64.efi.info
'''

    #
    # Build an ArgumentParser object to parse arguments.
    #

    parser = argparse.ArgumentParser(
                formatter_class=argparse.RawTextHelpFormatter,
                description=desc)

    #
    # Anonymous arguments.
    #

    parser.add_argument(
            'txt',
            help='An crash dump file. E.g., crash-dump.txt')

    #
    # Specific arguments
    #

    parser.add_argument(
            '-i',
            dest='info',
            help='Information of a executable file. E.g., bootx64.efi')  	

    #
    # Check arguments.
    #

    args = parser.parse_args()	

    return args

#
# Open the file fn, read it, and analyze the crash dump file.
#

def parse_crash_dump_file(fn):
	f = open(fn)
	out = {}

	for line in f:
		if line.find('X64 Exception Type') != -1:
			s0, s1 = line.split('-', 1)
			out['X64 Exception Type'] = s1.strip()

		elif line.find('ExceptionData') != -1:
			s0, s1 = line.split('-', 1)
			out['ExceptionData'] = s1.strip()
	
		else:
			matches = re.findall(r'(\w+)\s+\-\s+(\w+)', line)
			if matches != []:
				#lg(matches)
				for match in matches:
					out[match[0]] = match[1]

			matches = re.findall(r'(\w+)\=(\w+)', line)
			if matches != []:
				for match in matches:
					out[match[0]] = match[1]

	f.close()

	return out

#
# Open the file fn, read it, and analyze the crash dump file.
#

def parse_information_file(fn):
	f = open(fn)
	out = {}

	s = 'init'							# init, line0, line1
	sec_name = None	
	for line in f:
		if line.strip() == '':
			continue

		if s == 'init':
			res = re.match(r'\s+\d+\s\.\w+', line)
			if res != None:
				s = 'line0'

		elif s == 'line0':
			s = 'line1'

		elif s == 'line1':
			s = 'line0'

		#lg('%10s | %s' % (s, line.strip()))

		if s == 'line0':
			ls = line.split()
			sec_name = ls[1]
			out[sec_name] = {}
			out[sec_name]['Idx'] = ls[0]
			out[sec_name]['Size'] = ls[2]
			out[sec_name]['VMA'] = ls[3]
			out[sec_name]['LMA'] = ls[4]
			out[sec_name]['File off'] = ls[5]
			out[sec_name]['Align'] = ls[6]

		elif s == 'line1':
			assert sec_name != None, line
			ls = line.split()
			
			out[sec_name]['Attrs'] = []
			for v in ls:
				v = v.replace(',', '')
				out[sec_name]['Attrs'].append(v)

	f.close()

	return out

#
# Analyze the crash.
#

def analyze_crash(crash, info):

	#
	# Find the code section in info.
	#

	code_sec = None
	for sec_name, record in info.items():
		if 'READONLY' in record['Attrs'] and 'CODE' in record['Attrs']:
			code_sec = info[sec_name]
			break

	if code_sec == None:
		print('Error! the code section does not exist.')
		sys.exit(1)

	#
	# Read the hex strings, and transform them into integers.
	#

	ImageBase = int(crash['ImageBase'], 16) # transform hex str ImageBase as integer 
	print('ImageBase  = %x' % ImageBase)

	RIP = int(crash['RIP'], 16)             # transform hex str RIP as integer 
	print('RIP        = %x' % RIP)

	VMA = int(code_sec['VMA'], 16)          # transform hex str VMA as integer
	print('VMA        = %x' % VMA)
 
	Size = int(code_sec['Size'], 16)        # transform hex str Size as integer
	print('Size       = %x' % Size)

	#
	# Get the range address of the code in the memory.
	#

	code_begin = ImageBase + VMA
	print('code_begin = %x' % code_begin)

	code_end = ImageBase + VMA + Size
	print('code_end   = %x' % code_end)

	if not RIP in range(code_begin, code_end):
		print('RIP is not in the range.')
	else:
		print('RIP is in the range.') 

def main():

    #
    # Parse arguments
    #

    args = build_args()

    #
    # Check if the crash dump file exists.
    #

    if not os.path.exists(args.txt):
    	print('Error! The file does not exist.')
    	print(args.txt)
    	sys.exit(1)

    #
    # Parse the crash dump file.
    #

    crash = parse_crash_dump_file(args.txt)

    #
    # Build the memory map.
    #

    mem_map = {}
    mem_map['CR2'] = int(crash['CR2'], 16)
    mem_map['RBP'] = int(crash['RBP'], 16)
    mem_map['RSP'] = int(crash['RSP'], 16)
    mem_map['CR3'] = int(crash['CR3'], 16)
    mem_map['EntryPoint'] = int(crash['EntryPoint'], 16)
    mem_map['RIP'] = int(crash['RIP'], 16)
    mem_map['ImageBase'] = int(crash['ImageBase'], 16)

    #
    # Order the memory map by address.
    #

    sorted_mem_map = sorted(mem_map.items(), key=lambda item: item[1])

    #
    # Report the ordered memory map.
    #

    print('Memory Map:')
    for key, _ in reversed(sorted_mem_map):
    	print('    %-12s: %s' % (key, crash[key]))
    print('')

    #
    # Report caller and callee
    #

    print('%-16s          %-16s' % ('Caller-saved:', 'Callee-saved:'))
    print('RAX : %16s    RBX : %16s' % (crash['RAX'], crash['RBX']))
    print('RCX : %16s    RBP : %16s' % (crash['RCX'], crash['RBP']))
    print('RDX : %16s    RDI : %16s' % (crash['RDX'], crash['RDI']))
    print('R8  : %16s    RSI : %16s' % (crash['R8'],  crash['RSI']))
    print('R9  : %16s    R12 : %16s' % (crash['R9'],  crash['R12']))
    print('R10 : %16s    R13 : %16s' % (crash['R10'],  crash['R13']))
    print('R11 : %16s    R14 : %16s' % (crash['R11'],  crash['R14']))
    print('      %16s    R15 : %16s' % ('',  crash['R15']))
    print('')

    #
    # If the option -i, analyze the information file.
    #

    if args.info != None:

    	#
    	# Check if the info file exists.
    	#

	    if not os.path.exists(args.info):
	    	print('Error! The file does not exist.')
	    	print(args.info)
	    	sys.exit(-1)

	    #
	    # Parse the information file.
	    #

	    info = parse_information_file(args.info)

	    #
	    # Analyze the crash
	    # 

	    analyze_crash(crash, info)

if __name__ == '__main__':
	main()