#!/usr/bin/python

import sys

# To use:
# python
# > import gennodes
# > optab = gennodes.genoptabfromfile('NAMEOFOPTABFILE')
# > node = gennodes.nodefromoptab(optab)
# > emitnodes(node, open('NAMEOFOUTPUTFILE','w+'))
#
# will emit C code to generate an instruction node tree suitable
# for opdecode.cpp
#
# Theoretically you can use this with any RISC-like opcode
# map, expressed as a series of bitfields followed by the
# name of the operation.  Set `bits' to instruction word length
# However in actuality, because the bit reverse function is
# 16 bits only, it only works with 16 bit instructions

#table = open(sys.argv[1], 'r')
#nodes = open(sys.argv[2], 'w+')

bits = 16

def opval(x):
 try:
  v=int(x)
  return v
 except ValueError:
  return 0

def opmask(x):
 try:
  v=int(x)
  return 1
 except ValueError:
  return 0

def bytereverse(x):
 # google "bit twiddling hacks"
 b = int(x)&0xff
 return ((b*0x0202020202L)&0x010884422010L)%1023

def shortreverse(x):
 s = int(x)&0xffff
 return (bytereverse(x&0xff)<<8)|(bytereverse(x>>8))

def uniq(list):
 hash={}
 for item in list:
 	hash[item] = 1
 return hash.keys()

def genoptab(table):
  lineno = 0
  optab = []
  names = {}
  # parse lines into an op table
  for line in table.readlines():
    lineno+=1
    line.strip()
    if line[0] == '#': continue
    fields = line.split()
    if len(fields) == 0: continue
    if len(fields) <= bits:
      raise ValueError("%d: Must have at least %d fields (%d given)"%(lineno,bits+1,len(fields)))
    name = reduce(lambda a,b: a+' '+b, fields[bits:])
    tstname = name
    ni = 0
    while names.has_key(tstname):
    	tstname = "%s_%d"%(name,ni)
	ni += 1
    name = tstname
    names[name] = 1
    (mask,val) = reduce(lambda a,b: ((a[0]<<1)+opmask(b),(a[1]<<1)+opval(b)), \
                        [(opmask(fields[0]),opval(fields[0]))]+fields[1:bits])
    nonbitfields = uniq(fields[:bits])
    nonbitfields.count('0') and nonbitfields.remove('0')
    nonbitfields.count('1') and nonbitfields.remove('1')
    fieldnames = []
    for nbf in nonbitfields:
    	fieldnames.append([nbf, \
	                   reduce(lambda a,b: (a<<1)+int(b==nbf), \
			          [int(fields[0]==nbf)]+fields[1:bits])])
    optab.append((mask,val,name,fieldnames))
  
  optab.sort(lambda x,y: cmp(shortreverse(x[0]),shortreverse(y[0])))

  return optab

def genoptabfromfile(table):
  return genoptab(open(table, 'r'))

iopmask = 0
iopval = 1
iname = 2
ifieldnames = 3
ioptab = 4
ikids = 5

#nodes=[[0,0,None,[],optab,[]]]

def findkid(node,opent):
	for kid in node[ikids]:
		if (opent[iopval] & node[iopmask]) == kid[iopval]: return kid
	return None

def stepnode(node, prevmask):
	optab = node[ioptab]
	# blerk! ok, we set our mask to the "smallest" mask we can find
	# because everything's already sorted, that means first entry on
	# the list
	#
	# HOWEVER if the firs toptab entry is actually a terminating node,
	# we DON'T set the mask to that (if we are going to termiante on
	# this node, we don't want to mask anything, as a matter of fact)
	# But to account for potentially conflicting doo-dads, what we will
	# do instead is set the mask to the first mask that is not the same
	# as prevmask
	for opent in optab:
		if opent[iopmask] != prevmask: 
			node[iopmask] = opent[iopmask]
			break
	for opent in optab:
		if opent[iopmask] == prevmask:
			if not node[iname]:
				node[iname] = opent[iname]
			else: # a conflict...
				node[iname] += '_OR_' + opent[iname]
			# let someone else deal with the mess of possible
			# conflicts...
			node[ifieldnames].extend(opent[ifieldnames])
			continue
		kid = findkid(node, opent)
		if not kid:
			node[ikids].append( \
				[ 0, node[iopmask]&opent[iopval], None, [], \
				  [ opent ], [] ])
		else:
			kid[ioptab].append(opent)
	node[ioptab] = []
	for kid in node[ikids]:
		stepnode(kid, node[iopmask])

def nodefromoptab(optab):
	node = [ 0, 0, None, [], optab, [] ]
	stepnode(node, optab)
	return node

def emitinstr(node, outfile):
	print >>outfile, "enum nameNum {"
	print >>outfile, "  mcore_null,"
	emitinstrex(node,outfile, 0)
	print >>outfile, "};"
	print >>outfile, "instruc_t Instructions[] = {"
	print >>outfile, "{ \"\", 0 },"
	emitinstrex(node, outfile, 1)
	print >>outfile, "};"

def emitinstrex(node, outfile, mode):
	for kid in node[ikids]:
		emitinstrex(kid, outfile, mode)
	if node[iname]:
		if mode == 0:
			print >>outfile, "  mcore_%s,"%(node[iname].replace('.','_'),)
		else:
			print >>outfile, "{ \"%s\", 0 },"%(node[iname],)

# 32b numbers only
mod37bitpos = (
	32,0,1,26,2,23,27,0,3,16,24,30,28,11,0,13,4, \
	7,17,0,25,22,31,15,29,10,12,6,0,21,14,9,5, \
	20,8,19,18 \
	)
def lsb_index(v):
	return mod37bitpos[(-v & v) % 37]

def emitnodes(node, outfile):
	emitnodesex(node, outfile, 0)

def getopndval(field):
	return "((code&0x%04x)>>%d)"%(field[1],lsb_index(field[1]))

def emitopnds(node, outfile, c):
	pfx = "  "*c
	# pretty MCORE specific

	# ok I could use .index() but I don't want to do try/catch shit
	# because it requires annoying indentation
	fields = {}
#	fields = node[ifieldnames]
	for n in node[ifieldnames]:
		fields[n[0]] = n
	if fields.has_key('u'):
		outfile.write(pfx+"FILL DIS SHIT IN YO'SEF\n");
	else:
		if len(fields) == 3:
			outfile.write(pfx+"make_r(cmd.Op1, %s);\n"%(getopndval(fields['z']),))
			outfile.write(pfx+"make_displ(cmd.Op2, %s, %s);\n"%(getopndval(fields['r']), getopndval(fields['i'])))
			# rz, (rx,disp)
		elif len(fields) == 2:
			if fields.has_key('b'):
				outfile.write(pfx+"make_b(cmd.Op1, %s);\n"%(getopndval(fields['b']),))
				del fields['b']
			elif fields.has_key('d'):
				outfile.write(pfx+"make_d(cmd.Op1, %s);\n"%(getopndval(fields['d']),))
				del fields['d']
			else:
				outfile.write(pfx+"make_r(cmd.Op1, %s);\n"%(getopndval(fields['r']),))
				del fields['r']
			k=fields.keys()[0]
			outfile.write(pfx+"make_%s(cmd.Op2, %s);\n"%(k,getopndval(fields[k]),))
		elif len(fields) == 1:
			k=fields.keys()[0]
			outfile.write(pfx+"make_%s(cmd.Op1, %s);\n"%(k,getopndval(fields[k]),))

def emitinsn(node, outfile, c):
	pfx = "  "*c
	outfile.write(pfx+"// %s\n"%(node[iname],))
	emitopnds(node, outfile, c)
	outfile.write(pfx+"cmd.itype = mcore_%s;\n"%(node[iname],))
	outfile.write(pfx+"return 2;\n"); # all MCORE insns 2 bytes

# the resulting switch statement will REALLY not be pretty
# but its much faster than my original plan which was creating basically
# like a N-ary search tree and using a generic-type search algorithm on it
# (694 megainstructions per second, instead of only 8.3 megainstructions
# on a 1.4Ghz Athlon)
#
# OK what does this do?
# we have our n-ary search tree-like structure
# we are going to spit out code that starts at the root node and searches down
# for child nodes, using nested switch statements.  To facilitate table lookup
# in compiler-emitted switches, we try sort, mask, and right-shift all 
# switch argument.
def emitnodesex(node, outfile, c):
	if node[iname]: print "PROCESSING %s -> %d"%(node[iname],c)
	pfx = "  "*c
	if not node[ikids]:
		if node[iname]:
			emitinsn(node, outfile, c)
		else:
			outfile.write(pfx+"return 0; // BAD INSN\n");
		return
	node[ikids].sort(lambda x,y: cmp(x[iopval],y[iopval]))
	switch = "switch (((code - 0x%04x) & 0x%04x) >> %d)" %(node[ikids][0][iopval],node[iopmask],lsb_index(node[iopmask]))
	outfile.write(pfx+switch+" {\n")
	for kid in node[ikids]:
		outfile.write(pfx+"case 0x%04x: {\n" %(((kid[iopval]-node[ikids][0][iopval])>>lsb_index(node[iopmask]))))
		emitnodesex(kid, outfile, c+1)
		outfile.write(pfx+"} break;\n")
	# if we have a name, then we can terminate if none of the kids
	# matched, else match failed
	if node[iname]:
		outfile.write(pfx+"default: {\n");
		emitinsn(node, outfile, c+1)
		outfile.write(pfx+"} break;\n");
	else:
		outfile.write(pfx+"default: return 0;\n")
	outfile.write(pfx+"} // %s\n"%(switch,))

def doit(infile, outfile):
	optab = genoptabfromfile(infile)
	node = nodefromoptab(optab)
	of = open(outfile, 'w+')
	emitnodes(node, of)
	of.close()

if __name__ == "__main__":
	doit(sys.argv[1], sys.argv[2])

