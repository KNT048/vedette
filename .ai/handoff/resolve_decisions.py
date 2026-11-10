import sys
p=sys.argv[1]
L=open(p).read().split('\n')
n=0
while '<<<<<<< HEAD' in L:
    i=L.index('<<<<<<< HEAD'); j=L.index('=======',i); k=next(x for x in range(j,len(L)) if L[x].startswith('>>>>>>>'))
    rows=L[i+1:j]+L[j+1:k]
    assert all(r.startswith('| D-') for r in rows), rows
    seen=set(); out=[]
    for r in rows:
        key=r.split('|')[1].strip()
        if key in seen: continue
        seen.add(key); out.append(r)
    out.sort(key=lambda r:int(r.split('|')[1].strip()[2:]))
    L[i:k+1]=out; n+=1
open(p,'w').write('\n'.join(L)); print("resolved",n)
