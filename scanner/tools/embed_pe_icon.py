from pathlib import Path
import struct,sys,subprocess,tempfile,os

def pe_header(b):
  pe=struct.unpack_from('<I',b,0x3c)[0];assert b[pe:pe+4]==b'PE\0\0';
  number=struct.unpack_from('<H',b,pe+6)[0]; opt=pe+24; optsize=struct.unpack_from('<H',b,pe+20)[0]
  assert struct.unpack_from('<H',b,opt)[0]==0x20b
  sect=opt+optsize; sec=[]
  for n in range(number):
    off=sect+n*40;name=b[off:off+8].rstrip(b'\0').decode();vsize,va,rawsize,rawptr=struct.unpack_from('<IIII',b,off+8);sec.append((name,vsize,va,rawsize,rawptr))
  return pe,opt,sec

def resource_blob(ico,baseVA=0):
 data=Path(ico).read_bytes();reserved,kind,count=struct.unpack_from('<HHH',data)
 assert reserved==0 and kind==1
 images=[]; groups=[]
 for i in range(count):
  width,height,colors,res,planes,bits,size,off=struct.unpack_from('<BBBBHHII',data,6+i*16)
  images.append(data[off:off+size]);groups.append((width,height,colors,res,planes,bits,size,i+1))
 # build directories at offset 0, positions deterministic: root(32), type3(24), type14(24), each per id=24, 1 group=24
 # root has 2 entries; type 3 has count entries; type 14 has 1; each child name has one language entry
 blob=bytearray()
 def new_dir(n):
  off=len(blob);blob.extend(b'\0'*(16+n*8));struct.pack_into('<HH',blob,off+12,0,n);return off
 def ent(parent,index,id,suboffset,isdirectory=True):
  struct.pack_into('<II',blob,parent+16+index*8,id,(0x80000000 if isdirectory else 0)|suboffset)
 root=new_dir(2); d3=new_dir(count); d14=new_dir(1)
 ent(root,0,3,d3);ent(root,1,14,d14)
 # resource name level: each icon name numerical id
 lang=[]
 for i in range(count):
  node=new_dir(1);ent(d3,i,i+1,node);lang.append(node)
 group_node=new_dir(1);ent(d14,0,1,group_node)
 # data directory entries, aligned
 def aligned():
  while len(blob)%4: blob.append(0)
 datas=[]
 for node in lang+[group_node]:
  aligned();off=len(blob);blob.extend(b'\0'*16);ent(node,0,1033,off,False);datas.append(off)
 # append icons and group
 raw=[]
 for a in images:
  aligned();at=len(blob);blob.extend(a);raw.append((at,len(a)))
 g=bytearray(struct.pack('<HHH',0,1,count))
 for vals in groups:g.extend(struct.pack('<BBBBHHIH',*vals))
 aligned();at=len(blob);blob.extend(g);raw.append((at,len(g)))
 for i,(at,sz) in enumerate(raw):struct.pack_into('<IIII',blob,datas[i],baseVA+at,sz,0,0)
 return bytes(blob)

def install(exe,icon):
 exe=Path(exe); b=bytearray(exe.read_bytes()); pe,opt,secs=pe_header(b)
 assert all(s[0]!='.rsrc' for s in secs), 'Resource section already exists'
 n=len(secs); section_table=opt+struct.unpack_from('<H',b,pe+20)[0]
 new_header=section_table+n*40
 firstraw=min(s[4] for s in secs if s[4]>0)
 assert new_header+40<=firstraw,'No space for additional PE section header'
 section_align=struct.unpack_from('<I',b,opt+32)[0]
 file_align=struct.unpack_from('<I',b,opt+36)[0]
 def align(v,unit): return (v+unit-1)//unit*unit
 last_va=max(align(s[2]+s[1],section_align) for s in secs)
 va=last_va
 blob=resource_blob(icon,va)
 rawptr=align(len(b),file_align)
 rawsize=align(len(blob),file_align)
 if rawptr>len(b): b.extend(b'\0'*(rawptr-len(b)))
 b.extend(blob)
 if rawsize>len(blob):b.extend(b'\0'*(rawsize-len(blob)))
 # resource section header: name, VirtualSize, VirtualAddress, SizeOfRawData, PointerToRawData, reloc, linenum, counts, characteristics
 struct.pack_into('<8sIIIIIIHHI',b,new_header,b'.rsrc\0\0\0',len(blob),va,rawsize,rawptr,0,0,0,0,0x40000040)
 struct.pack_into('<H',b,pe+6,n+1)
 struct.pack_into('<I',b,opt+56,align(va+len(blob),section_align))
 struct.pack_into('<II',b,opt+112+2*8,va,len(blob))
 # clear stale checksum; Windows handles unsigned executables
 struct.pack_into('<I',b,opt+64,0)
 exe.write_bytes(b)
 print(exe.name, 'icon bytes',len(blob),'RVA',hex(va))

if __name__=='__main__':install(sys.argv[1],sys.argv[2])
