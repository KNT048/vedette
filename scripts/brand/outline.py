# Writes the brand SVGs (issue #826) from one geometry: logo lockups, app icon sources, favicon.svg, README hero, social preview.
# Text (the wordmark, the taglines) is Be Vietnam Pro (OFL-1.1, the app's own font from web/node_modules) converted to outlined
# paths, so no SVG needs a font at run time. An authoring step, run only when the logo or a tagline changes; then run `make brand`.
# The illustrations (web/src/assets/illustrations/) are hand-written and not made here.
# Needs Python 3 with: pip install fonttools==4.68.0 brotli==1.2.1 uharfbuzz==0.57.0 (a throwaway venv; nothing here ships).
# Usage: python3 scripts/brand/outline.py   (after pnpm --dir web install)
import io, re, os
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
R=os.path.abspath(os.path.join(os.path.dirname(__file__),'..','..'))
FD=R+'/web/node_modules/@fontsource/be-vietnam-pro/files/be-vietnam-pro-latin-%d-normal.woff'
_f={}
def font(w):
    if w not in _f:
        f=TTFont(FD%w); f.flavor=None; b=io.BytesIO(); f.save(b); _f[w]=(f,hb.Font(hb.Face(b.getvalue())))
    return _f[w]
def F(v,p=1):
    s=f'%.{p}f'%v
    if '.' in s: s=s.rstrip('0').rstrip('.')
    return '0' if s in ('-0','') else s
def text(t,w,size,x,y,track=0,p=1,join_tt=False):
    f,hf=font(w); up=f['head'].unitsPerEm; s=size/up
    buf=hb.Buffer(); buf.add_str(t); buf.guess_segment_properties(); hb.shape(hf,buf,{'kern':True,'liga':True})
    gs=f.getGlyphSet(); order=f.getGlyphOrder(); cx=0; out=[]
    for info,pos in zip(buf.glyph_infos,buf.glyph_positions):
        pen=SVGPathPen(gs,ntos=lambda v:F(v,p)); g=gs[order[info.codepoint]]
        g.draw(TransformPen(pen,(s,0,0,-s,x+(cx+pos.x_offset)*s,y)))
        out.append([order[info.codepoint],pen.getCommands()]); cx+=pos.x_advance+track*up
    if join_tt:  # one crossbar across both t's
        ts=[i for i,o in enumerate(out) if o[0]=='t']
        a,b=out[ts[0]][1],out[ts[1]][1]
        pat=r'(?=V(-?[\d.]+)H([\d.]+)V(-?[\d.]+)H)'
        r1=max((m for m in re.finditer(pat,a) if float(m.group(1))<float(m.group(3))),key=lambda m:float(m.group(2)))  # first t: crossbar right edge
        l2=min((m for m in re.finditer(pat,b) if float(m.group(1))>float(m.group(3))),key=lambda m:float(m.group(2)))  # second t: crossbar left edge
        out[ts[0]][1]=a[:r1.start(2)]+F(float(l2.group(2))+size*.014,p)+a[r1.end(2):]
    d=''.join(o[1] for o in out)
    return minify(d,p), cx*s

def minify(d,p=1):
    """Absolute M/L/H/V/Q/Z path -> per segment the shorter of absolute/relative, relative taken from the decoded (rounded) pen position."""
    toks=re.findall(r'[MLHVQZ]|-?\d*\.?\d+',d); i=0; cmd=None; segs=[]
    ar={'M':2,'L':2,'H':1,'V':1,'Q':4,'Z':0}
    while i<len(toks):
        t=toks[i]
        if t in ar: cmd=t; i+=1
        elif cmd=='M': cmd='L'
        n=[float(x) for x in toks[i:i+ar[cmd]]]; i+=ar[cmd]; segs.append((cmd,n))
    tok=lambda t:t[1:] if t.startswith('0.') else ('-'+t[2:] if t.startswith('-0.') else t)
    def join(prev,t): return t if prev is None or t.startswith('-') or (t.startswith('.') and '.' in prev) else ' '+t
    res='';last=None;prevn=None;cx=cy=sx=sy=0.0
    for c,n in segs:
        if c=='Z': res+='z'; last='z'; prevn=None; cx,cy=sx,sy; continue
        ra=[round(v,p) for v in n]
        if c=='H': rr=[round(n[0]-cx,p)]
        elif c=='V': rr=[round(n[0]-cy,p)]
        else: rr=[round(v-(cx if j%2==0 else cy),p) for j,v in enumerate(n)]
        A=[tok(F(v,p)) for v in ra]; Rl=[tok(F(v,p)) for v in rr]
        if len(''.join(A))+len(A)<=len(''.join(Rl))+len(Rl): use,lc,dec=A,c,ra
        else: use,lc=Rl,c.lower(); dec=[rr[0]+cx] if c=='H' else [rr[0]+cy] if c=='V' else [v+(cx if j%2==0 else cy) for j,v in enumerate(rr)]
        if c=='H': cx=dec[0]
        elif c=='V': cy=dec[0]
        else: cx,cy=dec[-2],dec[-1]
        if c=='M': sx,sy=cx,cy
        if lc==last and lc not in 'Mm': body=''
        else: body=lc; prevn=None
        for t in use: body+=join(prevn,t); prevn=t
        res+=body; last={'M':'L','m':'l'}.get(lc,lc)
    return res
ACC={'light':'#1d5a45','dark':'#6bbe9c'}; INK={'light':'#18211d','dark':'#e3eae7'}; SIG='#e7a748'
# bare mark, 24 box: V from (2,3.8) to (11.2,22), right arm stops at 46 %, signal dot (20.4,3.8) r3.2
def mark(tx,ty,k,vc,dc,sw=3.6,r=3.2,p=1):
    q=lambda x,y:F(tx+x*k,p)+' '+F(ty+y*k,p)
    ex,ey=11.2+9.2*.46,22-18.2*.46
    return (f'<path d="M{q(2,3.8)} {q(11.2,22)} {q(ex,ey)}" fill="none" stroke="{vc}" stroke-width="{F(sw*k,p)}" stroke-linecap="round" stroke-linejoin="round"/>'
            f'<circle cx="{F(tx+20.4*k,p)}" cy="{F(ty+3.8*k,p)}" r="{F(r*k,p)}" fill="{dc}"/>')
def svg(w,h,body,label=None):
    a=f' role="img" aria-label="{label}"' if label else ''
    return f'<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 {F(w)} {F(h)}"{a}>{body}</svg>\n'
def put(path,s): open(R+'/'+path,'w').write(s)
WM=lambda x,y,col,size=100: text('Vedette',600,size,x,y,track=-.015,join_tt=True)
wm_w=WM(0,0,'')[1]
for th in ('light','dark'):
    sx='' if th=='light' else '-dark'; a,i=ACC[th],INK[th]
    # wordmark: cap height 74 at size 100; V's left side bearing ~2.2
    k=4.3; mh=24*k; gap=26; my=-37-mh/2; oy=-my
    d,_=WM(mh+gap-2.2,oy,i)
    put(f'docs/brand/logo-horizontal{sx}.svg',svg(mh+gap-4.4+wm_w,mh+1,mark(0,0,k,a,SIG)+f'<path d="{d}" fill="{i}"/>','Vedette'))
    k=5; mh=24*k; gap=34
    d,_=WM(-2.2,mh+gap+74,i)
    put(f'docs/brand/logo-stacked{sx}.svg',svg(wm_w-4.4,mh+gap+75,mark((wm_w-4.4-mh)/2,0,k,a,SIG)+f'<path d="{d}" fill="{i}"/>','Vedette'))
    put(f'docs/brand/mark{sx}.svg',svg(24,24,mark(0,0,1,a,SIG),'Vedette'))
# app icons, 32 grid; mark bounds centre (11.9,12.2)
def tile(k,rx,sw=3.6,r=3.2,full=False):
    tx,ty=16-11.9*k,16-12.2*k
    bg=f'<rect width="32" height="32" rx="{F(rx)}" fill="#1d5a45"/>' if not full else '<path fill="#1d5a45" d="M0 0h32v32H0z"/>'
    return svg(32,32,bg+mark(tx,ty,k,'#fff',SIG,sw,r,p=2))
put('docs/brand/app-icon.svg',tile(.78,7.2))
put('docs/brand/app-icon-maskable.svg',tile(.62,0,full=True))
put('docs/brand/app-icon-ios.svg',tile(.72,0,full=True))
put('web/public/favicon.svg',tile(1,7,sw=4.2,r=3.6))
# scene used by the hero and the social preview: the illustration family's lookout, with the signal landing on one device
def scene(tx,ty,k,c,sig,soft):
    return (f'<g transform="translate({F(tx)} {F(ty)}) scale({F(k,2)})" fill="none" stroke="{c}" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">'
     f'<path d="M66 106 220 56v76H66z" fill="{c}" stroke="none" opacity="{soft}"/><path d="M20 132h200" opacity=".35"/>'
     '<path d="m66 106 154-50" stroke-dasharray="2 6" opacity=".5"/>'
     '<rect x="26" y="106" width="44" height="26" rx="5"/><path d="M34 114v10m6-10v10m6-10v10"/>'
     f'<circle cx="60" cy="119" r="2.2" fill="{c}" stroke="none"/>'
     '<rect x="96" y="113" width="24" height="15" rx="2"/><path d="M91 132h34"/>'
     '<rect x="140" y="96" width="20" height="36" rx="3"/><path d="M145 104h10m-10 7h10"/>'
     f'<circle cx="150" cy="124" r="1.6" fill="{c}" stroke="none"/>'
     '<rect x="174" y="116" width="34" height="16" rx="3"/><path d="m180 116-4-14m28 14 4-14m-22 22h2m5 0h2m5 0h2"/>'
     f'<path d="M66 106 145 87.5" opacity=".8"/><circle cx="150" cy="86" r="5" fill="{sig}" stroke="none"/></g>')
TAG='Know early. Know exactly. Know what to do.'
SUB='Free, open-source alerts when a vulnerability exploited'
SUB2='in the wild matches a device you own, with the fix.'
for th in ('light','dark'):
    sx='' if th=='light' else '-dark'; a,i=ACC[th],INK[th]; muted={'light':'#56615c','dark':'#9aa7a2'}[th]
    k=.84; mh=24*k*4.3/4.3  # logo at 84 % of the master
    lk=4.3*.84; lm=24*lk
    d,_=text('Vedette',600,84,lm+26*.84-2.2*.84,130+37*.84,track=-.015,join_tt=True)
    t,_=text(TAG,500,30,4,232)
    body=mark(0,130-lm/2,lk,a,SIG)+f'<path d="{d}" fill="{i}"/><path d="{t}" fill="{muted}"/>'+scene(700,-20,2.4,a,SIG,'.08' if th=='light' else '.1')
    put(f'docs/brand/readme-hero{sx}.svg',svg(1280,360,body,'Vedette: know early, know exactly, know what to do'))
# social preview, 1280x640, accent background
lk=4.3*1.0; lm=24*lk
d,_=text('Vedette',600,100,96+lm+26-2.2,170+37,track=-.015,join_tt=True)
tl=''.join(text(x,500,40,100,y)[0] for x,y in (('Know early.',300),('Know exactly.',352),('Know what to do.',404)))
s1,_=text('Free, open-source alerts when an exploited',400,26,100,470); s2,_=text('vulnerability matches a device you own.',400,26,100,506)
body=('<path fill="#1d5a45" d="M0 0h1280v640H0z"/>'+mark(96,170-lm/2,lk,'#fff',SIG)+f'<path d="{d}" fill="#fff"/><path d="{tl}" fill="#fff"/>'
      f'<path d="{s1}{s2}" fill="#fff" opacity=".75"/>'+scene(690,506-132*2.4,2.4,'#fff',SIG,'.07'))
put('docs/brand/social-preview.svg',svg(1280,640,body))
