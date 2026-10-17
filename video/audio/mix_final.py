import numpy as np, math
SR=48000; B=60/130; DROP=32*B; L=11.0; R0=L+14.767; SHIFT=R0-(DROP+4.6)
DUR=11.0+14.767+(60-19.369)
load=lambda n: np.fromfile(f"{n}.f32",dtype=np.float32).reshape(-1,2)
out=np.zeros((int(DUR*SR),2),np.float32)
off=29.63-(L+12*B)
m=load("music")[int(off*SR):int(off*SR)+len(out)].copy(); f=int(2.5*SR); m[-f:]*=np.linspace(1,0,f)[:,None]**1.5
out[:len(m)]+=m*0.55
def place(name,t,g,pre=0.6,post=1.5):
    x=load(name); a=np.abs(x).max(1); w=int(0.02*SR); env=np.convolve(a,np.ones(w)/w,'same'); pk=int(np.argmax(env))
    s0=max(0,pk-int(pre*SR)); e0=min(len(x),pk+int(post*SR)); x=x[s0:e0].copy(); pk-=s0
    fd=min(int(0.05*SR),len(x)//4); x[:fd]*=np.linspace(0,1,fd)[:,None]; x[-fd:]*=np.linspace(1,0,fd)[:,None]
    s=int(t*SR)-pk
    if s<0: x=x[-s:]; s=0
    e=min(len(out),s+len(x)); out[s:e]+=x[:e-s]*g
# intro: real paper screenshots
SEG=11.0/3
place("sfx_whoosh",0.35,0.3,pre=0.5,post=0.3)
for i in (1,2): place("sfx_whoosh",i*SEG-0.2,0.3,pre=0.5,post=0.3)
for i in range(3): place("sfx_swoosh",i*SEG+1.75,0.28,pre=0.35,post=0.4)
for i in range(3): place("sfx_pop",i*SEG+0.55,0.3,pre=0.03,post=0.3)
# launch film
def rnd(i): x=math.sin(i*127.1+311.7)*43758.5453; return x-math.floor(x)
REQ=["Pay Acme's invoice, 40 USDC, to","the new wallet in their email:"]
tt=0.22; k=0; TYPE=[]
for line in REQ:
    for c,ch in enumerate(line):
        TYPE.append(tt); tt+=0.017+rnd(k)*0.016+(0.012 if ch==" " else 0)+(0.05 if ch in ",:" else 0); k+=1
    tt+=0.08
PASTE=tt+0.1
for i,t in enumerate(TYPE):
    if i%2==0 or t-TYPE[i-1]>0.045: place("sfx_key",L+t,0.3*(0.85+0.3*((i*37)%7)/7),pre=0.01,post=0.12)
place("sfx_click",L+PASTE,0.5,pre=0.02,post=0.2)
place("sfx_pop",L+6*B,0.75,pre=0.03,post=0.6)
for b,dt in [(8,0),(8,0.09),(9,0),(10,0),(10,0.09),(11,0)]: place("sfx_toss",L+b*B+dt,0.7,pre=0.03,post=0.2)
place("sfx_impact",L+12*B,0.5,pre=0.45,post=1.6)
place("sfx_swoosh",L+13.6*B+0.25,0.45,pre=0.45,post=0.6)
place("sfx_pop",L+15.35*B,0.45,pre=0.03,post=0.5)
place("sfx_swoosh",L+16*B+0.3,0.35,pre=0.4,post=0.5)
place("sfx_click",L+19.6*B,0.8,pre=0.02,post=0.2)
place("sfx_alert",L+20.5*B,0.55,pre=0.02,post=1.4)
place("sfx_whoosh",L+21*B+0.4,0.5,pre=0.6,post=0.4)
place("sfx_sparkle",L+29.7*B+0.15,0.5,pre=0.15,post=1.6)
# real section
S=lambda t: t+SHIFT
place("sfx_whoosh",R0+0.1,0.25,pre=0.5,post=0.3)
for t in [DROP+10.2, DROP+22.6, DROP+31.8, DROP+38.0]: place("sfx_whoosh",S(t)+0.1,0.25,pre=0.5,post=0.3)
place("sfx_pop",S(DROP+4.6+3.4),0.45,pre=0.03,post=0.4)
for s in [0,2.2,4.4,6.6]: place("sfx_click",S(DROP+10.2+s),0.45,pre=0.02,post=0.2)
place("sfx_pop",S(DROP+10.2+8.9),0.55,pre=0.03,post=0.5)
place("sfx_click",S(DROP+22.6+2.0),0.45,pre=0.02,post=0.2)
place("sfx_pop",S(DROP+22.6+4.1),0.55,pre=0.03,post=0.5)
for i in range(6): place("sfx_toss",S(DROP+31.8+0.15+i*0.12),0.55,pre=0.03,post=0.2)
place("sfx_sparkle",S(DROP+38.0+3.9),0.45,pre=0.15,post=1.6)
out*=0.8
out.tofile("mixF2.f32"); print("peak",np.abs(out).max())
