#!/usr/bin/env python3
# ============================================================
# TRACE 1.0 -- Total Risk Assessment & Computed Exposure
# 100-Artifact Deep Scan Edition
# Windows Forensic Exposure Scanner
# ============================================================
# T - Total
# R - Risk
# A - Assessment
# C - Computed
# E - Exposure
# ============================================================
# By Yonas Abeselom | Independent Security Researcher
# Email  : yonas_abeselom@protonmail.com
# REDACT : https://github.com/yonasabeselom/redact
# AAD-50 : https://github.com/yonasabeselom/aad50
# ============================================================

import sys, os, datetime, struct, codecs, glob, traceback
try:
    import ctypes, winreg, subprocess
except ImportError as _ie:
    print("TRACE 1.0 -- Total Risk Assessment & Computed Exposure\nRequires Windows with Python 3.6+")
    input("Press Enter to exit..."); sys.exit(1)

def _ansi_on():
    try: ctypes.windll.kernel32.SetConsoleMode(ctypes.windll.kernel32.GetStdHandle(-11),7)
    except: pass
_ansi_on()

R=" \033[91m"; Y=" \033[93m"; G=" \033[92m"; W=" \033[97m"
DI="\033[90m"; BO="\033[1m"; RS="\033[0m"; OR="\033[38;5;214m"
R=R.strip(); Y=Y.strip(); G=G.strip(); W=W.strip()
TC={"HIGH":R,"MEDIUM":Y,"LOW":G}
SEP="\u2500"*78; SEP2="\u2550"*78

AUTHOR  = "Yonas Abeselom"
TITLE   = "Independent Security Researcher"
EMAIL   = "yonas_abeselom@protonmail.com"
REDACT  = "https://github.com/yonasabeselom/redact"
AAD50   = "https://github.com/yonasabeselom/aad50"
AAD50_SF = "https://sourceforge.net/projects/aad50/"

def _on_crash(et,ev,tb):
    print(); print(R+"  !! TRACE ERROR !!"+RS)
    traceback.print_exception(et,ev,tb)
    print(); input("  Press Enter to exit...")
sys.excepthook=_on_crash

def _is_admin():
    try: return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except: return False

if not _is_admin():
    print(); print(OR+BO+"  TRACE 1.0 -- Forensic Exposure Scanner"+RS)
    print(W+"  Administrator privileges required."+RS)
    print(DI+"  A UAC prompt will appear -- click Yes to continue."+RS); print()
    try:
        import time
        script=os.path.abspath(sys.argv[0])
        extra=" ".join('"{}"'.format(a) for a in sys.argv[1:])
        params='"{}"'.format(script)+(" "+extra if extra else "")
        ret=ctypes.windll.shell32.ShellExecuteW(None,"runas",sys.executable,params,None,1)
        if ret<=32: raise RuntimeError("ShellExecuteW returned "+str(ret))
        time.sleep(2)
    except Exception as _e:
        print(R+"  Could not auto-elevate: "+str(_e)+RS)
        print(W+"  Fix: right-click CMD -> Run as administrator, then run again."+RS)
        input("  Press Enter to exit...")
    sys.exit()

# ---------------------------------------------------------------------------
def _sz(p):
    try:
        b=os.path.getsize(p)
        return "{:.1f} MB".format(b/1048576) if b>1048576 else "{} KB".format(b//1024)
    except: return "unknown"
def _mt(p):
    try: return datetime.datetime.fromtimestamp(os.path.getmtime(p)).strftime("%Y-%m-%d %H:%M")
    except: return "unknown"
def _rot13(s):
    try: return codecs.decode(s,"rot_13")
    except: return s
def _ropen(h,p):
    try: return winreg.OpenKey(h,p,0,winreg.KEY_READ|winreg.KEY_WOW64_64KEY)
    except: return None
def _rvals(k):
    if not k: return
    i=0
    while True:
        try: n,d,_=winreg.EnumValue(k,i); yield n,d; i+=1
        except OSError: break
def _rsubs(k):
    if not k: return
    i=0
    while True:
        try: yield winreg.EnumKey(k,i); i+=1
        except OSError: break
def _ft(data,off=0):
    try:
        ft=struct.unpack_from("<Q",data,off)[0]
        if ft: return (datetime.datetime(1601,1,1)+datetime.timedelta(microseconds=ft//10)).strftime("%Y-%m-%d %H:%M")
    except: pass
    return ""
def _run(cmd,timeout=10):
    try: return subprocess.check_output(cmd,stderr=subprocess.DEVNULL,timeout=timeout,creationflags=subprocess.CREATE_NO_WINDOW).decode(errors="ignore")
    except: return ""
LOC=lambda:os.environ.get("LOCALAPPDATA","")
ROAM=lambda:os.environ.get("APPDATA","")
USER=lambda:os.environ.get("USERPROFILE","")
TEMP=lambda:os.environ.get("TEMP","")
def _ok(exposed,summary,items=None): return {"exposed":exposed,"summary":summary,"items":items or []}
def _found(summary,items): return _ok(True,summary,items)
def _clean(summary): return _ok(False,summary)

# ============================================================================
# SCAN FUNCTIONS (original 50)
# ============================================================================
def s_amcache():
    p="C:\\Windows\\AppCompat\\Programs\\Amcache.hve"
    return _found("Present -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Modified: "+_mt(p),"  Every program run: name, path, SHA-1 hash, first/last run timestamp."]) if os.path.exists(p) else _clean("Not found")
def s_shimcache():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\AppCompatCache")
    if not k: return _clean("Not accessible")
    items=["  Value '{}': {} bytes".format(n,len(d) if isinstance(d,bytes) else str(d)) for n,d in _rvals(k)]
    winreg.CloseKey(k)
    return _found("{} value(s)".format(len(items)),items+["  Every .exe touched on disk -- includes never-run executables."]) if items else _clean("Empty")
def s_bam():
    base="SYSTEM\\CurrentControlSet\\Services\\bam\\State\\UserSettings"
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,base)
    if not k: return _clean("BAM not accessible")
    users=list(_rsubs(k)); winreg.CloseKey(k)
    items,total=[],0
    for sid in users:
        uk=_ropen(winreg.HKEY_LOCAL_MACHINE,base+"\\"+sid)
        if not uk: continue
        ent=[(n,d) for n,d in _rvals(uk) if n not in("SequenceNumber","Version") and n.startswith("\\\\")]
        total+=len(ent)
        if ent:
            items.append("  SID: {} ({} entries)".format(sid,len(ent)))
            for n,d in ent[:15]: items.append("    {}  {}".format(n,"["+_ft(d)+"]" if isinstance(d,bytes) and len(d)>=8 and _ft(d) else ""))
            if len(ent)>15: items.append("    ... and {} more".format(len(ent)-15))
        winreg.CloseKey(uk)
    return _found("{} BAM record(s)".format(total),items) if total else _clean("No BAM entries")
def s_srum():
    p="C:\\Windows\\System32\\sru\\SRUDB.dat"
    return _found("SRUDB.dat -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Per-app network/CPU usage -- 60 days."]) if os.path.exists(p) else _clean("Not found")
def s_usb():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR")
    if not k: return _clean("Not accessible")
    classes=list(_rsubs(k)); winreg.CloseKey(k)
    items,total=[],0
    for cls in classes:
        ck=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\"+cls)
        if not ck: continue
        for dev in _rsubs(ck):
            total+=1
            dk=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Enum\\USBSTOR\\"+cls+"\\"+dev)
            fn=next((d for n,d in _rvals(dk) if n=="FriendlyName" and isinstance(d,str)),"") if dk else ""
            if dk: winreg.CloseKey(dk)
            items.append("  Device: {}\\{}".format(cls,dev))
            if fn: items.append("  Name  : "+fn)
        winreg.CloseKey(ck)
    return _found("{} USB device(s)".format(total),items) if total else _clean("No USB history")
def s_prefetch():
    d="C:\\Windows\\Prefetch"
    if not os.path.isdir(d): return _clean("Prefetch disabled")
    files=sorted([f for f in os.listdir(d) if f.lower().endswith(".pf")],key=lambda f:os.path.getmtime(os.path.join(d,f)),reverse=True)
    if not files: return _clean("No prefetch files")
    items=["  {:<55} {}".format("Filename","Last Run"),"  "+"-"*73]
    for f in files[:30]: items.append("  {:<55} {}".format(f,_mt(os.path.join(d,f))))
    if len(files)>30: items.append("  ... and {} more".format(len(files)-30))
    return _found("{} execution records".format(len(files)),items)
def s_userassist():
    base="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\UserAssist"
    k=_ropen(winreg.HKEY_CURRENT_USER,base)
    if not k: return _clean("Not accessible")
    guids=list(_rsubs(k)); winreg.CloseKey(k)
    items,total=[],0
    for guid in guids:
        ck=_ropen(winreg.HKEY_CURRENT_USER,base+"\\"+guid+"\\Count")
        if not ck: continue
        for n,d in _rvals(ck):
            if n=="UEME_CTLSESSION": continue
            decoded=_rot13(n); rc,ts="",""
            if isinstance(d,bytes) and len(d)>=16:
                try:
                    c=struct.unpack_from("<I",d,4)[0]
                    if 0<c<99999: rc="runs={}".format(c)
                except: pass
                ts=_ft(d,8)
            suf="  ["+"  ".join(x for x in [rc,ts] if x)+"]" if(rc or ts) else ""
            items.append("  "+decoded+suf); total+=1
        winreg.CloseKey(ck)
    show=items[:40]+(["  ... and {} more".format(total-40)] if total>40 else [])
    return _found("{} app launch records".format(total),show) if total else _clean("No entries")
def s_shellbags():
    total,items=0,[]
    for path in ["Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\BagMRU","Software\\Microsoft\\Windows\\Shell\\BagMRU"]:
        k=_ropen(winreg.HKEY_CURRENT_USER,path)
        if k:
            cnt=len(list(_rsubs(k))); winreg.CloseKey(k); total+=cnt
            items.append("  {}: {} entries".format(path.split("\\")[-1],cnt))
    if total:
        items.append("  Every folder ever opened, including from removed USB drives.")
        return _found("{} Shell Bag entries".format(total),items)
    return _clean("No Shell Bags")
def s_vss():
    out=_run(["vssadmin","list","shadows"],timeout=15)
    cnt=out.count("Shadow Copy Volume")
    if not cnt: return _clean("No shadow copies")
    return _found("{} Volume Shadow Copy(ies)".format(cnt),["  "+l.strip() for l in out.splitlines() if l.strip()][:30])
def s_winsearch():
    p="C:\\ProgramData\\Microsoft\\Search\\Data\\Applications\\Windows\\Windows.edb"
    return _found("Windows.edb -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Full-text index including deleted documents."]) if os.path.exists(p) else _clean("Not found")
def s_recall():
    loc=LOC()
    cands=[os.path.join(loc,"CoreAIPlatform.00"),os.path.join(loc,"CoreAIPlatform")]
    cands+=glob.glob(os.path.join(loc,"Packages","MicrosoftWindows.Client.AIX*"))
    found=[p for p in cands if os.path.isdir(p)]
    if not found: return _clean("Not found")
    items=[]
    for p in found:
        nb,nc=0,0
        for r,_,fs in os.walk(p):
            for f in fs:
                try: nb+=os.path.getsize(os.path.join(r,f))
                except: pass
                nc+=1
        items+=["  Path: "+p,"  Files: {} ({:.1f} MB)".format(nc,nb/1048576)]
    items.append("  AI screenshots + semantic timeline of everything on screen.")
    return _found("Recall data in {} location(s)".format(len(found)),items)
def s_eventlogs():
    d="C:\\Windows\\System32\\winevt\\Logs"
    if not os.path.isdir(d): return _clean("Not found")
    files=[(f,os.path.join(d,f)) for f in os.listdir(d) if f.lower().endswith(".evtx")]
    if not files: return _clean("No .evtx files")
    total_mb=sum(os.path.getsize(p) for _,p in files)/1048576
    pri=["Security","System","Application","PowerShell","TerminalServices","TaskScheduler"]
    sfiles=sorted(files,key=lambda x:not any(t.lower() in x[0].lower() for t in pri))
    items=["  Total: {} files -- {:.1f} MB".format(len(files),total_mb),""]
    for n,p in sfiles[:35]:
        if os.path.getsize(p): items.append("  {:<62} {:>8}".format(os.path.splitext(n)[0],_sz(p)))
    if len(files)>35: items.append("  ... and {} more".format(len(files)-35))
    return _found("{} log files -- {:.1f} MB".format(len(files),total_mb),items)
def s_rdp():
    items=[]
    for path in ["Software\\Microsoft\\Terminal Server Client\\Default","Software\\Microsoft\\Terminal Server Client\\Servers"]:
        k=_ropen(winreg.HKEY_CURRENT_USER,path)
        if k:
            for n,d in _rvals(k):
                if isinstance(d,str) and d: items.append("  "+n+": "+d)
            for sk in _rsubs(k): items.append("  Server: "+sk)
            winreg.CloseKey(k)
    return _found("{} RDP target(s)".format(len(items)),items) if items else _clean("No RDP history")
def s_wifi():
    out=_run(["netsh","wlan","show","profiles"])
    profiles=[l.split(":")[-1].strip() for l in out.splitlines() if "All User Profile" in l or "User Profile" in l]
    if profiles: return _found("{} WiFi profile(s)".format(len(profiles)),["  {:>3}. {}".format(i+1,p) for i,p in enumerate(profiles)])
    return _clean("No saved WiFi profiles")
def s_timeline():
    base=os.path.join(LOC(),"ConnectedDevicesPlatform")
    if not os.path.isdir(base): return _clean("Not found")
    dbs=glob.glob(os.path.join(base,"*","ActivitiesCache.db"))
    if not dbs: return _clean("ActivitiesCache.db not found")
    items=["  {} -- {}".format(db,_sz(db)) for db in dbs]
    items.append("  Full Windows Timeline: every app opened, file accessed, website visited.")
    return _found("{} ActivitiesCache.db file(s)".format(len(dbs)),items)
def s_pshistory():
    p=os.path.join(ROAM(),"Microsoft","Windows","PowerShell","PSReadLine","ConsoleHost_history.txt")
    if not os.path.exists(p): return _clean("No PowerShell history")
    try:
        lines=open(p,encoding="utf-8",errors="ignore").readlines()
        items=["  File: "+p,"  Commands: {}".format(len(lines)),""]
        items+=["  "+l.rstrip() for l in lines[-30:]]
        if len(lines)>30: items.insert(3,"  (showing last 30 of {})".format(len(lines)))
        return _found("{} PS command(s)".format(len(lines)),items)
    except Exception as e: return _found("Present (read error: {})".format(e),[p])
def s_mountpoints():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\MountPoints2")
    if not k: return _clean("Not found")
    mounts=list(_rsubs(k)); winreg.CloseKey(k)
    if not mounts: return _clean("No mount points")
    items=["  "+m for m in mounts[:20]]
    if len(mounts)>20: items.append("  ... and {} more".format(len(mounts)-20))
    items.append("  Every volume (USB, network, local) ever mounted.")
    return _found("{} mount point(s)".format(len(mounts)),items)
def s_runkeys():
    paths=[(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Run"),(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\RunOnce"),(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"),(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\RunOnce")]
    items,total=[],0
    for hive,path in paths:
        k=_ropen(hive,path)
        if not k: continue
        vals=[(n,d) for n,d in _rvals(k) if isinstance(d,str)]
        if vals:
            items.append("  ["+path.split("\\")[-1]+"]")
            for n,d in vals: items.append("    {} = {}".format(n,d)); total+=1
        winreg.CloseKey(k)
    return _found("{} startup Run entry(ies)".format(total),items) if total else _clean("Run keys empty")
def s_installed():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall")
    if not k: return _clean("Not accessible")
    programs=[]
    for sk_name in _rsubs(k):
        sk=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\"+sk_name)
        if sk:
            name=next((d for n,d in _rvals(sk) if n=="DisplayName" and isinstance(d,str)),None)
            if name: programs.append(name)
            winreg.CloseKey(sk)
    winreg.CloseKey(k)
    if programs:
        items=["  Total: {} installed program(s)".format(len(programs)),""]
        items+=["  - "+p for p in sorted(programs)[:30]]
        if len(programs)>30: items.append("  ... and {} more".format(len(programs)-30))
        return _found("{} installed software entries".format(len(programs)),items)
    return _clean("No entries")
def s_remote_tools():
    items=[]
    for p in ["C:\\Program Files\\TeamViewer\\Connections_incoming.txt","C:\\Program Files (x86)\\TeamViewer\\Connections_incoming.txt"]:
        if os.path.exists(p):
            try:
                lines=open(p,encoding="utf-8",errors="ignore").readlines()
                items.append("  TeamViewer: {} incoming connection(s)".format(len(lines)))
                items+=["  "+l.strip() for l in lines[:5]]
            except: items.append("  TeamViewer log: "+p)
    ad=os.path.join(ROAM(),"AnyDesk","ad.trace")
    if os.path.exists(ad): items.append("  AnyDesk trace: "+ad+" ("+_sz(ad)+")")
    for rp in glob.glob(os.path.join(USER(),"AppData","Roaming","RustDesk","*.toml")): items.append("  RustDesk: "+rp)
    return _found("Remote access tool log(s) found",items) if items else _clean("No remote tool logs")
def s_recent():
    r=os.path.join(ROAM(),"Microsoft","Windows","Recent")
    if not os.path.isdir(r): return _clean("Not found")
    files=sorted([f for f in os.listdir(r) if f.lower().endswith(".lnk")],key=lambda f:os.path.getmtime(os.path.join(r,f)),reverse=True)
    if not files: return _clean("Empty")
    items=["  {:<57} {}".format("File","Accessed"),"  "+"-"*73]
    for f in files[:30]: items.append("  {:<57} {}".format(os.path.splitext(f)[0],_mt(os.path.join(r,f))))
    if len(files)>30: items.append("  ... and {} more".format(len(files)-30))
    return _found("{} recent file reference(s)".format(len(files)),items)
def s_jumplists():
    jl=os.path.join(ROAM(),"Microsoft","Windows","Recent","AutomaticDestinations")
    if not os.path.isdir(jl): return _clean("Not found")
    files=os.listdir(jl)
    if not files: return _clean("Empty")
    items=["  {} ({})".format(f,_sz(os.path.join(jl,f))) for f in sorted(files)[:25]]
    if len(files)>25: items.append("  ... and {} more".format(len(files)-25))
    return _found("{} jump list file(s)".format(len(files)),items)
def s_mru_docs():
    base="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RecentDocs"
    k=_ropen(winreg.HKEY_CURRENT_USER,base)
    if not k: return _clean("Not found")
    types=list(_rsubs(k)); winreg.CloseKey(k); items=[]
    for ext in types:
        ek=_ropen(winreg.HKEY_CURRENT_USER,base+"\\"+ext)
        if not ek: continue
        vals=[(n,d) for n,d in _rvals(ek) if n!="MRUListEx" and isinstance(d,bytes)]
        if vals:
            items.append("  Ext: {} -- {} doc(s)".format(ext or "(root)",len(vals)))
            for _,d in vals[:4]:
                try:
                    fn=d[:d.index(b"\x00\x00")].decode("utf-16-le",errors="ignore")
                    if fn: items.append("    - "+fn)
                except: pass
        winreg.CloseKey(ek)
    return _found("{} doc type bucket(s)".format(len(types)),items) if items else _clean("Empty")
def s_mru_run():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\RunMRU")
    if not k: return _clean("Not found")
    items=["  [{}] {}".format(n,str(d).rstrip(chr(1))) for n,d in _rvals(k) if n!="MRUList" and isinstance(d,str) and d]
    winreg.CloseKey(k)
    return _found("{} Run command(s)".format(len(items)),items) if items else _clean("Empty")
def s_typed_paths():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\TypedPaths")
    if not k: return _clean("Not found")
    items=["  [{}] {}".format(n,d) for n,d in _rvals(k) if isinstance(d,str) and d]
    winreg.CloseKey(k)
    return _found("{} typed path(s)".format(len(items)),items) if items else _clean("Empty")
def s_searchhist():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\WordWheelQuery")
    if not k: return _clean("Not found")
    items=[]
    for n,d in _rvals(k):
        if n=="MRUListEx": continue
        term=d.decode("utf-16-le",errors="ignore").rstrip("\x00") if isinstance(d,bytes) else str(d)
        if term: items.append("  "+term)
    winreg.CloseKey(k)
    return _found("{} search term(s)".format(len(items)),items) if items else _clean("Empty")
def s_thumbcache():
    dbs=glob.glob(os.path.join(LOC(),"Microsoft","Windows","Explorer","thumbcache_*.db"))
    if not dbs: return _clean("Not found")
    total_b=sum(os.path.getsize(db) for db in dbs)
    items=["  {:<35} {:>8}  {}".format(os.path.basename(db),_sz(db),_mt(db)) for db in sorted(dbs)]
    items.append("  {:.1f} MB total -- thumbnails prove files existed after deletion.".format(total_b/1048576))
    return _found("{} thumbcache file(s)".format(len(dbs)),items)
def s_browsers():
    loc,roam=LOC(),ROAM()
    B={"Chrome":os.path.join(loc,"Google","Chrome","User Data","Default","History"),"Edge":os.path.join(loc,"Microsoft","Edge","User Data","Default","History"),"Brave":os.path.join(loc,"BraveSoftware","Brave-Browser","User Data","Default","History"),"Vivaldi":os.path.join(loc,"Vivaldi","User Data","Default","History"),"Arc":os.path.join(loc,"Arc","User Data","Default","History"),"Firefox":os.path.join(roam,"Mozilla","Firefox","Profiles"),"Zen":os.path.join(roam,"zen","Profiles"),"Pale Moon":os.path.join(roam,"Moonchild Productions","Pale Moon"),"Tor":os.path.join(roam,"Tor Browser"),"Opera":os.path.join(roam,"Opera Software","Opera Stable"),"Opera GX":os.path.join(roam,"Opera Software","Opera GX Stable")}
    found,items=[],[]
    for name,path in B.items():
        if os.path.exists(path): found.append(name); items.append("  {:<12} {}".format(name,path))
    return _found("{} browser(s): {}".format(len(found),", ".join(found)),items) if found else _clean("No browser history found")
def s_wer():
    loc=LOC(); total,items=0,[]
    for sub in ["ReportQueue","ReportArchive"]:
        d=os.path.join(loc,"Microsoft","Windows","WER",sub)
        if os.path.isdir(d):
            reps=os.listdir(d); total+=len(reps)
            items+=["  "+r for r in reps[:10]]
            if len(reps)>10: items.append("  ... and {} more in {}".format(len(reps)-10,sub))
    return _found("{} error report(s)".format(total),items) if total else _clean("No reports")
def s_crashdumps():
    d="C:\\Windows\\Minidump"
    if not os.path.isdir(d): return _clean("Not found")
    dumps=sorted([f for f in os.listdir(d) if f.lower().endswith(".dmp")],key=lambda f:os.path.getmtime(os.path.join(d,f)),reverse=True)
    if not dumps: return _clean("No dumps")
    items=["  {:<40} {:>8}  {}".format(f,_sz(os.path.join(d,f)),_mt(os.path.join(d,f))) for f in dumps[:15]]
    if len(dumps)>15: items.append("  ... and {} more".format(len(dumps)-15))
    return _found("{} crash dump(s)".format(len(dumps)),items)
def s_lnk():
    roam,u=ROAM(),USER(); items,total=[],0
    for label,path in [("Recent",os.path.join(roam,"Microsoft","Windows","Recent")),("Desktop",os.path.join(u,"Desktop")),("Start Menu",os.path.join(roam,"Microsoft","Windows","Start Menu")),("SendTo",os.path.join(roam,"Microsoft","Windows","SendTo"))]:
        if os.path.isdir(path):
            lnks=[f for f in os.listdir(path) if f.lower().endswith(".lnk")]; total+=len(lnks)
            if lnks:
                items.append("  {} ({}):".format(label,len(lnks)))
                for f in sorted(lnks)[:8]: items.append("    - "+f)
                if len(lnks)>8: items.append("    ... and {} more".format(len(lnks)-8))
    return _found("{} LNK file(s)".format(total),items) if total else _clean("None found")
def s_clipboard():
    cb=os.path.join(LOC(),"Microsoft","Windows","Clipboard")
    if os.path.isdir(cb):
        files=os.listdir(cb)
        if files: return _found("{} clipboard history item(s)".format(len(files)),["  Clipboard: "+cb,"  {} item(s) stored".format(len(files))]+["  "+f for f in files[:10]])
    return _clean("No clipboard history")
def s_stickynotes():
    paths=glob.glob(os.path.join(LOC(),"Packages","Microsoft.MicrosoftStickyNotes*","LocalState","plum.sqlite"))
    if paths:
        items=["  {} ({})".format(p,_sz(p)) for p in paths]
        items.append("  Contains all sticky note content in SQLite.")
        return _found("{} Sticky Notes database(s)".format(len(paths)),items)
    return _clean("Not found")
def s_office_mru():
    items,total=[],0
    try:
        k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Office")
        if not k: return _clean("Office not found")
        versions=list(_rsubs(k)); winreg.CloseKey(k)
        for ver in versions:
            for app in ["Word","Excel","PowerPoint","Access"]:
                fk=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Office\\{}\\{}\\File MRU".format(ver,app))
                if fk:
                    vals=[(n,d) for n,d in _rvals(fk) if n.startswith("Item") and isinstance(d,str)]
                    if vals:
                        items.append("  {} {} ({} files):".format(app,ver,len(vals)))
                        for n,d in vals[:5]: items.append("    - "+d.split("*")[-1])
                        total+=len(vals)
                    winreg.CloseKey(fk)
    except: pass
    return _found("{} Office recent file(s)".format(total),items) if total else _clean("No Office MRU entries")
def s_notifications():
    paths=glob.glob(os.path.join(LOC(),"Microsoft","Windows","Notifications","*.db"))
    if not paths: paths=glob.glob(os.path.join(LOC(),"Microsoft","Windows","Notifications","wpndatabase.db"))
    if paths:
        items=["  {} ({})".format(p,_sz(p)) for p in paths]+["  Notification history: alerts, messages, banners."]
        return _found("{} notification DB(s)".format(len(paths)),items)
    return _clean("Not found")
def s_print_spool():
    d="C:\\Windows\\System32\\spool\\PRINTERS"
    if not os.path.isdir(d): return _clean("Not found")
    files=[f for f in os.listdir(d) if f.lower().endswith((".spl",".shd"))]
    items=["  Spool dir: "+d]
    if files: items+=["  "+f for f in files[:10]]; return _found("{} spool file(s)".format(len(files)),items)
    items.append("  Directory exists (historical jobs cleared)")
    return _found("Print spooler dir present",items)
def s_remote_tools2(): pass  # merged above
def s_dns():
    out=_run(["ipconfig","/displaydns"])
    entries=[l.strip() for l in out.splitlines() if "Record Name" in l]
    if entries:
        items=["  "+e for e in entries[:30]]
        if len(entries)>30: items.append("  ... and {} more".format(len(entries)-30))
        return _found("{} DNS cache entry(ies)".format(len(entries)),items)
    return _clean("DNS cache empty or not accessible")
def s_startup_folder():
    locs=[os.path.join(ROAM(),"Microsoft","Windows","Start Menu","Programs","Startup"),"C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"]
    items,total=[],0
    for d in locs:
        if os.path.isdir(d):
            files=os.listdir(d); total+=len(files)
            if files:
                items.append("  {}: {} item(s)".format(d,len(files)))
                items+=["    - "+f for f in files]
    return _found("{} startup item(s)".format(total),items) if total else _clean("Startup folders empty")
def s_defender():
    base="C:\\ProgramData\\Microsoft\\Windows Defender\\Scans\\History"
    if not os.path.isdir(base): return _clean("Not found")
    total=sum(len(fs) for _,_,fs in os.walk(base))
    return _found("{} Defender history file(s)".format(total),["  "+base,"  {} file(s)".format(total),"  Detections, quarantine records, scan logs."] ) if total else _clean("No scan history")
def s_netinterfaces():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces")
    if not k: return _clean("Not accessible")
    ifaces=list(_rsubs(k)); winreg.CloseKey(k)
    items,total=[],0
    for iface in ifaces:
        ik=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\Tcpip\\Parameters\\Interfaces\\"+iface)
        if not ik: continue
        vals={n:d for n,d in _rvals(ik) if n in("IPAddress","DhcpIPAddress","DhcpServer","Domain","DhcpDomain")}
        if vals:
            total+=1; items.append("  Interface: "+iface)
            for n,d in vals.items():
                v=d[0] if isinstance(d,(list,tuple)) else str(d)
                if v and v not in("0.0.0.0",""): items.append("    {}: {}".format(n,v))
        winreg.CloseKey(ik)
    return _found("{} interface(s) with history".format(total),items) if total else _clean("No interface history")
def s_temp():
    items,grand=[],0
    for label,d in [("User TEMP",TEMP()),("Windows Temp","C:\\Windows\\Temp")]:
        if os.path.isdir(d):
            try:
                contents=os.listdir(d); cnt=len(contents)
                sz=sum(os.path.getsize(os.path.join(d,f)) for f in contents if os.path.isfile(os.path.join(d,f)))/1048576
                grand+=cnt; items.append("  {:<20}: {} items ({:.1f} MB)".format(label,cnt,sz))
            except: items.append("  "+label+": not accessible")
    return _found("{} item(s) in temp dirs".format(grand),items) if grand else _clean("Temp dirs empty")
def s_recycle():
    total,items=0,[]
    for drv in "CDEFGH":
        rb=drv+":\\$Recycle.Bin"
        if os.path.isdir(rb):
            try:
                cnt=sum(len(fs) for _,_,fs in os.walk(rb))
                if cnt: total+=cnt; items.append("  Drive {}: {} item(s)".format(drv,cnt))
            except: pass
    return _found("{} item(s) in Recycle Bin".format(total),items) if total else _clean("Empty")
def s_iconcache():
    loc=LOC()
    found=[(p,_sz(p),_mt(p)) for p in [os.path.join(loc,"IconCache.db")]+glob.glob(os.path.join(loc,"Microsoft","Windows","Explorer","iconcache_*.db")) if os.path.exists(p)]
    return _found("{} icon cache file(s)".format(len(found)),["  {} ({}) mod {}".format(p,sz,mt) for p,sz,mt in found]) if found else _clean("Not found")
def s_pagefile():
    p="C:\\pagefile.sys"
    return _found("pagefile.sys -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  RAM overflow: keys, passwords, process memory."]) if os.path.exists(p) else _clean("Not found")
def s_hiberfil():
    p="C:\\hiberfil.sys"
    return _found("hiberfil.sys -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Full RAM image: active keys, open files, clipboard."]) if os.path.exists(p) else _clean("Hibernation disabled")
def s_downloads():
    d=os.path.join(USER(),"Downloads")
    if not os.path.isdir(d): return _clean("Not found")
    try:
        files=os.listdir(d); total=len(files)
        sz=sum(os.path.getsize(os.path.join(d,f)) for f in files if os.path.isfile(os.path.join(d,f)))/1048576
        items=["  Path: "+d,"  {} item(s) ({:.1f} MB)".format(total,sz)]+["  - "+f for f in sorted(files)[:20]]
        if total>20: items.append("  ... and {} more".format(total-20))
        return _found("{} item(s) ({:.1f} MB)".format(total,sz),items) if total else _clean("Downloads empty")
    except: return _clean("Not accessible")
def s_scheduled_tasks():
    d="C:\\Windows\\System32\\Tasks"
    if not os.path.isdir(d): return _clean("Not found")
    tasks=[]
    for root,dirs,files in os.walk(d):
        for f in files:
            if not f.endswith(".manifest"): tasks.append(os.path.relpath(os.path.join(root,f),d))
    if tasks:
        items=["  Total: {} task(s)".format(len(tasks)),""]+["  "+t for t in sorted(tasks)[:25]]
        if len(tasks)>25: items.append("  ... and {} more".format(len(tasks)-25))
        return _found("{} scheduled task(s)".format(len(tasks)),items)
    return _clean("No tasks")
def s_hosts_file():
    p="C:\\Windows\\System32\\drivers\\etc\\hosts"
    if not os.path.exists(p): return _clean("Not found")
    try:
        lines=open(p,encoding="utf-8",errors="ignore").readlines()
        custom=[l.rstrip() for l in lines if l.strip() and not l.strip().startswith("#")]
        if custom: return _found("{} custom host entry(ies)".format(len(custom)),["  Path: "+p]+["  "+l for l in custom])
        return _clean("Hosts file clean (default only)")
    except: return _clean("Not readable")
def s_winsupdate():
    paths=["C:\\Windows\\Logs\\CBS\\CBS.log","C:\\Windows\\WindowsUpdate.log"]
    found=[(p,_sz(p),_mt(p)) for p in paths if os.path.exists(p)]
    if found: return _found("{} update log(s)".format(len(found)),["  {} ({}) mod {}".format(p,sz,mt) for p,sz,mt in found]+["  Contains Windows Update and component install history."])
    return _clean("Update logs not found")
def s_credmanager():
    out=_run(["cmdkey","/list"])
    entries=[l.strip() for l in out.splitlines() if "Target" in l or "User" in l]
    if entries: return _found("{} Credential Manager entry(ies)".format(len([e for e in entries if "Target" in e])),["  "+e for e in entries])
    return _clean("No stored credentials")

# ============================================================================
# NEW HIGH-TIER SCAN FUNCTIONS (50 additional)
# ============================================================================
def n_muicache():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Classes\\Local Settings\\Software\\Microsoft\\Windows\\Shell\\MuiCache")
    if not k: return _clean("Not found")
    items=["  "+n for n,d in _rvals(k) if n.endswith(".FriendlyAppName") and isinstance(d,str)][:40]
    winreg.CloseKey(k)
    return _found("{} application name cache entry(ies)".format(len(items)),items+["  Maps every executed .exe path to its display name."]) if items else _clean("Empty")
def n_opensave():
    base="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\OpenSavePidlMRU"
    k=_ropen(winreg.HKEY_CURRENT_USER,base)
    if not k: return _clean("Not found")
    types=list(_rsubs(k)); winreg.CloseKey(k)
    items=[]
    for ext in types:
        ek=_ropen(winreg.HKEY_CURRENT_USER,base+"\\"+ext)
        if ek:
            cnt=sum(1 for n,d in _rvals(ek) if n!="MRUListEx")
            if cnt: items.append("  Extension '{}': {} entry(ies)".format(ext,cnt))
            winreg.CloseKey(ek)
    return _found("{} OpenSave MRU bucket(s) -- every file opened via dialog".format(len(items)),items) if items else _clean("Empty")
def n_lastvisited():
    base="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedPidlMRU"
    k=_ropen(winreg.HKEY_CURRENT_USER,base)
    if not k:
        base2="Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\ComDlg32\\LastVisitedMRU"
        k=_ropen(winreg.HKEY_CURRENT_USER,base2)
    if not k: return _clean("Not found")
    cnt=sum(1 for n,d in _rvals(k) if n!="MRUListEx"); winreg.CloseKey(k)
    return _found("{} LastVisited folder entry(ies) -- folders accessed via file dialogs".format(cnt),[]) if cnt else _clean("Empty")
def n_netprofiles():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles")
    if not k: return _clean("Not found")
    items=[]
    for guid in _rsubs(k):
        pk=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Profiles\\"+guid)
        if pk:
            name=next((d for n,d in _rvals(pk) if n=="ProfileName" and isinstance(d,str)),guid)
            cat=next((d for n,d in _rvals(pk) if n=="Category"),"")
            items.append("  {} (category: {})".format(name,cat))
            winreg.CloseKey(pk)
    winreg.CloseKey(k)
    return _found("{} network profile(s) -- every network ever connected".format(len(items)),items) if items else _clean("No profiles")
def n_mapped_drives():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Network")
    if not k: return _clean("No mapped drives")
    drives=[]
    for letter in _rsubs(k):
        dk=_ropen(winreg.HKEY_CURRENT_USER,"Network\\"+letter)
        if dk:
            path=next((d for n,d in _rvals(dk) if n=="RemotePath" and isinstance(d,str)),"")
            drives.append("  Drive {}: {}".format(letter,path))
            winreg.CloseKey(dk)
    winreg.CloseKey(k)
    return _found("{} mapped network drive(s)".format(len(drives)),drives) if drives else _clean("No mapped drives")
def n_logonui():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Authentication\\LogonUI")
    if not k: return _clean("Not found")
    items=["  {}: {}".format(n,d) for n,d in _rvals(k) if isinstance(d,str) and d and n in("LastLoggedOnUser","LastLoggedOnDisplayName","LastLoggedOnSAMUser")]
    winreg.CloseKey(k)
    return _found("Last logged on user recorded",items) if items else _clean("No logon data")
def n_ntuser_dat():
    p=os.path.join(USER(),"NTUSER.DAT")
    if os.path.exists(p): return _found("NTUSER.DAT -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Modified: "+_mt(p),"  User's entire registry hive: every setting, MRU, activity."])
    return _clean("Not found")
def n_usrclass_dat():
    p=os.path.join(LOC(),"Microsoft","Windows","UsrClass.dat")
    if os.path.exists(p): return _found("UsrClass.dat -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Shell classes hive: thumbnails, Shell Bags, file associations."])
    return _clean("Not found")
def n_setupapi():
    p="C:\\Windows\\inf\\setupapi.dev.log"
    if not os.path.exists(p):
        p="C:\\Windows\\setupapi.dev.log"
    if os.path.exists(p):
        try:
            lines=open(p,encoding="utf-8",errors="ignore").readlines()
            installs=[l.rstrip() for l in lines if "Device Install" in l or "dvi:" in l.lower()][:20]
            return _found("SetupAPI log -- {} device install events".format(len(installs)),["  Path: "+p,"  Size: "+_sz(p)]+installs)
        except: return _found("SetupAPI log present".format(),["  Path: "+p,"  Size: "+_sz(p)])
    return _clean("Not found")
def n_wmi_repo():
    d="C:\\Windows\\System32\\wbem\\Repository"
    if os.path.isdir(d):
        sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(d) for f in fs)/1048576
        return _found("WMI Repository -- {:.1f} MB".format(sz),["  Path: "+d,"  Size: {:.1f} MB".format(sz),"  WMI subscriptions used for persistence. Contains event consumers."])
    return _clean("Not found")
def n_teams():
    loc,roam=LOC(),ROAM()
    paths=[os.path.join(roam,"Microsoft","Teams"),os.path.join(loc,"Packages","MSTeams_8wekyb3d8bbwe")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        items=[]
        for p in found:
            try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(p) for f in fs)/1048576
            except: sz=0
            items.append("  {} ({:.1f} MB)".format(p,sz))
        items.append("  Messages, files, call logs cached locally.")
        return _found("Teams data in {} location(s)".format(len(found)),items)
    return _clean("Not found")
def n_discord():
    p=os.path.join(ROAM(),"discord")
    if os.path.isdir(p):
        cache=os.path.join(p,"Cache"); db=os.path.join(p,"Local Storage")
        items=["  Path: "+p]
        if os.path.isdir(cache):
            cnt=len(os.listdir(cache)); items.append("  Cache: {} item(s)".format(cnt))
        if os.path.isdir(db): items.append("  Local Storage: present")
        items.append("  Messages, media, guild data cached locally.")
        return _found("Discord data folder present",items)
    return _clean("Not found")
def n_trace_desktop():
    paths=[os.path.join(ROAM(),"Signal"),os.path.join(LOC(),"Signal")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        items=["  {} ({})".format(p,_sz(p) if os.path.isfile(p) else "folder") for p in found]
        items.append("  Signal Desktop messages database (SQLite + SQLCipher).")
        return _found("Signal Desktop data present",items)
    return _clean("Not found")
def n_telegram():
    p=os.path.join(ROAM(),"Telegram Desktop")
    if os.path.isdir(p):
        tdata=os.path.join(p,"tdata")
        items=["  Path: "+p]
        if os.path.isdir(tdata):
            try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(tdata) for f in fs)/1048576
            except: sz=0
            items.append("  tdata: {:.1f} MB -- session keys and message cache.".format(sz))
        return _found("Telegram Desktop data present",items)
    return _clean("Not found")
def n_whatsapp():
    paths=[os.path.join(LOC(),"Packages","5319275A.WhatsAppDesktop_cv1g1gvanyjgm"),os.path.join(ROAM(),"WhatsApp")]
    found=[p for p in paths if os.path.isdir(p)]
    if found: return _found("WhatsApp Desktop data present",["  "+p for p in found]+["  Local message database and media cache."])
    return _clean("Not found")
def n_zoom():
    paths=[os.path.join(ROAM(),"Zoom"),os.path.join(LOC(),"Zoom")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        items=["  "+p for p in found]; total_mb=0
        for p in found:
            try: total_mb+=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(p) for f in fs)/1048576
            except: pass
        items.append("  {:.1f} MB -- meeting recordings, chat logs, crash reports.".format(total_mb))
        return _found("Zoom data in {} location(s)".format(len(found)),items)
    return _clean("Not found")
def n_slack():
    p=os.path.join(ROAM(),"Slack")
    if os.path.isdir(p):
        try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(p) for f in fs)/1048576
        except: sz=0
        return _found("Slack data -- {:.1f} MB".format(sz),["  Path: "+p,"  {:.1f} MB -- workspace data, messages, files.".format(sz)])
    return _clean("Not found")
def n_onedrive():
    paths=[os.path.join(USER(),"OneDrive"),os.path.join(LOC(),"Microsoft","OneDrive")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        items=[]
        for p in found:
            try: files=sum(len(fs) for _,_,fs in os.walk(p)); items.append("  {} -- {} files".format(p,files))
            except: items.append("  "+p)
        items.append("  Sync logs contain metadata of all synced files, including deleted.")
        return _found("OneDrive data in {} location(s)".format(len(found)),items)
    return _clean("Not found")
def n_windows_old():
    p="C:\\Windows.old"
    if os.path.isdir(p):
        try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(p) for f in fs)/1073741824
        except: sz=0
        return _found("Windows.old -- {:.1f} GB".format(sz),["  Path: C:\\Windows.old","  Size: {:.1f} GB".format(sz),"  Previous Windows installation -- entire old user profile present.","  Investigators can access all old user data from previous OS."])
    return _clean("Not found")
def n_win_installer():
    d="C:\\Windows\\Installer"
    if not os.path.isdir(d): return _clean("Not found")
    files=os.listdir(d); total_mb=0
    try: total_mb=sum(os.path.getsize(os.path.join(d,f)) for f in files if os.path.isfile(os.path.join(d,f)))/1073741824
    except: pass
    return _found("{} MSI/MSP installer(s) -- {:.1f} GB".format(len(files),total_mb),["  Path: "+d,"  {} installer files".format(len(files)),"  {:.1f} GB -- cached MSI/MSP of every installed program.".format(total_mb),"  Used to repair/reinstall programs. Hashes tie installs to specific software."])
def n_bluetooth():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices")
    if not k: return _clean("No Bluetooth history")
    devices=[]
    for mac in _rsubs(k):
        dk=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Devices\\"+mac)
        name=""
        if dk:
            name=next((d.decode("utf-8",errors="ignore").rstrip("\x00") for n,d in _rvals(dk) if n=="Name" and isinstance(d,bytes)),"")
            winreg.CloseKey(dk)
        devices.append("  {} {}".format(mac,"-- "+name if name else ""))
    winreg.CloseKey(k)
    return _found("{} Bluetooth device(s) ever paired".format(len(devices)),devices) if devices else _clean("No paired devices")
def n_ngc():
    d="C:\\Windows\\ServiceProfiles\\LocalService\\AppData\\Local\\Microsoft\\NGC"
    if os.path.isdir(d):
        try: cnt=sum(len(fs) for _,_,fs in os.walk(d))
        except: cnt=0
        return _found("Windows Hello NGC -- {} file(s)".format(cnt),["  Path: "+d,"  {} file(s)".format(cnt),"  PIN, fingerprint, face authentication cryptographic keys.","  Unique per device per user -- identity proof."])
    return _clean("Not found")
def n_wsl():
    locs=[os.path.join(LOC(),"Packages")]
    wsl_dirs=glob.glob(os.path.join(LOC(),"Packages","*CanonicalGroupLimited*"))+glob.glob(os.path.join(LOC(),"Packages","*Ubuntu*"))+glob.glob(os.path.join(LOC(),"Packages","*Debian*"))
    bash_histories=[]
    for d in wsl_dirs:
        for hist in glob.glob(os.path.join(d,"LocalState","rootfs","root",".bash_history"))+glob.glob(os.path.join(d,"LocalState","rootfs","home","*",".bash_history")):
            bash_histories.append(hist)
    if wsl_dirs or bash_histories:
        items=["  WSL distro folder(s): {}".format(len(wsl_dirs))]+["  "+d for d in wsl_dirs[:5]]
        if bash_histories:
            items.append("  Bash histories:")
            for bh in bash_histories[:5]: items.append("    "+bh)
        items.append("  WSL can be used to run tools that evade Windows artifact capture.")
        return _found("WSL installation(s) found",items)
    out=_run(["wsl","--list","--quiet"],timeout=5)
    if out.strip(): return _found("WSL distributions: "+out.strip(),["  Run 'wsl --list' for details."])
    return _clean("WSL not installed")
def n_hyperv():
    d="C:\\ProgramData\\Microsoft\\Windows\\Hyper-V"
    if os.path.isdir(d):
        vms=glob.glob(os.path.join(d,"Virtual Machines","*.xml"))
        return _found("{} Hyper-V VM config(s)".format(len(vms)),["  "+v for v in vms]+["  Virtual machine images may contain separate forensic evidence."])
    return _clean("Hyper-V not found")
def n_virtualbox():
    vbox=os.path.join(USER(),".VirtualBox","VirtualBox.xml")
    vms=glob.glob(os.path.join(USER(),"VirtualBox VMs","*","*.vbox"))
    if os.path.exists(vbox) or vms:
        items=["  VirtualBox config: "+vbox] if os.path.exists(vbox) else []
        items+=["  VM: "+v for v in vms[:10]]
        return _found("{} VirtualBox VM(s)".format(len(vms)),items)
    return _clean("VirtualBox not found")
def n_vmware():
    paths=[os.path.join(ROAM(),"VMware"),os.path.join(USER(),"Documents","Virtual Machines")]
    found=[p for p in paths if os.path.isdir(p)]
    vms=glob.glob(os.path.join(USER(),"Documents","Virtual Machines","*","*.vmx"))
    if found or vms:
        items=["  "+p for p in found]+["  VMX: "+v for v in vms[:10]]
        return _found("VMware data / {} VM(s)".format(len(vms)),items)
    return _clean("VMware not found")
def n_active_connections():
    out=_run(["netstat","-ano"],timeout=15)
    conns=[l.strip() for l in out.splitlines() if "ESTABLISHED" in l or "LISTENING" in l]
    if conns:
        items=["  "+c for c in conns[:30]]
        if len(conns)>30: items.append("  ... and {} more".format(len(conns)-30))
        return _found("{} active/listening connection(s)".format(len(conns)),items)
    return _clean("No connections or not accessible")
def n_arp_cache():
    out=_run(["arp","-a"],timeout=10)
    entries=[l.strip() for l in out.splitlines() if "dynamic" in l.lower() or "static" in l.lower()]
    if entries:
        items=["  "+e for e in entries[:30]]
        return _found("{} ARP cache entry(ies) -- recently contacted IP/MAC pairs".format(len(entries)),items)
    return _clean("ARP cache empty")
def n_edge_webcache():
    cache=os.path.join(LOC(),"Microsoft","Windows","WebCache","WebCacheV01.dat")
    if os.path.exists(cache): return _found("IE/Edge WebCache -- "+_sz(cache),["  Path: "+cache,"  Size: "+_sz(cache),"  Modified: "+_mt(cache),"  ESE database of browsing history, cookies, downloaded files.","  Survives InPrivate mode in some cases."])
    return _clean("Not found")
def n_bits_jobs():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\BITS")
    bits_db="C:\\ProgramData\\Microsoft\\Network\\Downloader"
    items=[]
    if k: items+=["  BITS registry key present"]; winreg.CloseKey(k)
    if os.path.isdir(bits_db):
        files=os.listdir(bits_db)
        items+=["  DB path: "+bits_db,"  {} BITS transfer file(s)".format(len(files))]
        items+=["  "+f for f in files[:10]]
    if items:
        items.append("  BITS used by Windows Update and malware for covert downloads.")
        return _found("BITS transfer data present",items)
    return _clean("No BITS data")
def n_biometric():
    d="C:\\Windows\\System32\\WinBioDatabase"
    if os.path.isdir(d):
        files=glob.glob(os.path.join(d,"*.DAT"))
        return _found("{} biometric database file(s)".format(len(files)),["  Path: "+d]+["  "+f+" ("+_sz(f)+")" for f in files]+["  Fingerprint and face recognition templates."])
    return _clean("Not found")
def n_appcompat_flags():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Compatibility Assistant\\Store")
    if not k: return _clean("Not found")
    items=["  "+n for n,d in _rvals(k)][:30]
    winreg.CloseKey(k)
    return _found("{} AppCompatFlags entry(ies) -- manually run compatibility programs".format(len(items)),items) if items else _clean("Empty")
def n_memory_dmp():
    paths=["C:\\Windows\\MEMORY.DMP","C:\\Windows\\memory.dmp"]
    for p in paths:
        if os.path.exists(p): return _found("MEMORY.DMP -- "+_sz(p),["  Path: "+p,"  Size: "+_sz(p),"  Full kernel memory dump -- entire RAM captured at BSOD.","  Contains encryption keys, process memory, network state."])
    return _clean("No kernel memory dump")
def n_sysvolinfo():
    d="C:\\System Volume Information"
    if os.path.isdir(d):
        try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(d) for f in fs)/1073741824
        except: sz=0
        return _found("System Volume Info -- {:.1f} GB".format(sz),["  Path: "+d,"  {:.1f} GB".format(sz),"  VSS snapshots, system restore points, indexing data.","  Investigators recover deleted files from restore points."])
    return _clean("Not accessible")
def n_delivery_opt():
    d="C:\\Windows\\SoftwareDistribution\\DeliveryOptimization"
    if not os.path.isdir(d): d="C:\\Windows\\SoftwareDistribution"
    if os.path.isdir(d):
        try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(d) for f in fs)/1073741824
        except: sz=0
        return _found("Delivery Optimization cache -- {:.1f} GB".format(sz),["  Path: "+d,"  {:.1f} GB".format(sz),"  P2P Windows Update cache -- records of received files and peers."])
    return _clean("Not found")
def n_win_update_ds():
    d="C:\\Windows\\SoftwareDistribution\\DataStore"
    if os.path.isdir(d):
        dbs=glob.glob(os.path.join(d,"*.edb"))+glob.glob(os.path.join(d,"Logs","*.log"))
        return _found("{} Windows Update DataStore file(s)".format(len(dbs)),["  Path: "+d]+["  "+f+" ("+_sz(f)+")" for f in dbs[:10]]+["  Full Windows Update install history and pending downloads."])
    return _clean("Not found")
def n_browser_ext():
    loc=LOC(); found=[]
    for browser,path in [("Chrome",os.path.join(loc,"Google","Chrome","User Data","Default","Extensions")),("Edge",os.path.join(loc,"Microsoft","Edge","User Data","Default","Extensions")),("Brave",os.path.join(loc,"BraveSoftware","Brave-Browser","User Data","Default","Extensions"))]:
        if os.path.isdir(path):
            exts=os.listdir(path); found.append("  {} -- {} extension(s)".format(browser,len(exts)))
            for ext in exts[:5]: found.append("    ID: "+ext)
    return _found("Browser extensions found",found+["  Extension IDs reveal installed tools, password managers, VPNs."]) if found else _clean("No browser extensions found")
def n_cortana_data():
    paths=glob.glob(os.path.join(LOC(),"Packages","Microsoft.549981C3F5F10_*"))+glob.glob(os.path.join(LOC(),"Packages","Microsoft.Windows.Cortana_*"))
    if paths:
        items=[]
        for p in paths:
            try: sz=sum(os.path.getsize(os.path.join(r,f)) for r,_,fs in os.walk(p) for f in fs)/1048576
            except: sz=0
            items.append("  {} ({:.1f} MB)".format(p,sz))
        items.append("  Cortana AI assistant queries, voice data, search history.")
        return _found("Cortana data in {} location(s)".format(len(paths)),items)
    return _clean("Not found")
def n_ms_account():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\IdentityStore\\Cache")
    items=[]
    if k:
        for guid in _rsubs(k):
            ck=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\IdentityStore\\Cache\\"+guid+"\\AccountMetadata")
            if ck:
                for n,d in _rvals(ck):
                    if n=="AccountName" and isinstance(d,str): items.append("  Account: "+d)
                winreg.CloseKey(ck)
        winreg.CloseKey(k)
    return _found("{} Microsoft Account(s) linked".format(len(items)),items+["  Syncs data to OneDrive, Edge, Office 365."]) if items else _clean("No Microsoft Account data")
def n_appx_apps():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Classes\\ActivatableClasses\\Package")
    if not k: return _clean("Not found")
    apps=[sk for sk in _rsubs(k)]; winreg.CloseKey(k)
    items=["  Total: {} UWP/Store app(s)".format(len(apps)),""]
    items+=["  "+a for a in sorted(apps)[:30]]
    if len(apps)>30: items.append("  ... and {} more".format(len(apps)-30))
    return _found("{} UWP/Store apps registered".format(len(apps)),items) if apps else _clean("No apps")
def n_startup_approved():
    paths=[(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run"),(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Explorer\\StartupApproved\\Run")]
    items=[]
    for hive,path in paths:
        k=_ropen(hive,path)
        if k:
            for n,d in _rvals(k):
                status="ENABLED" if isinstance(d,bytes) and len(d)>=4 and d[0]==2 else "DISABLED"
                items.append("  {} [{}]".format(n,status))
            winreg.CloseKey(k)
    return _found("{} startup approval entry(ies)".format(len(items)),items+["  DISABLED entries show programs that WERE running -- may indicate cleanup attempt."]) if items else _clean("Not found")
def n_remote_assist():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SYSTEM\\CurrentControlSet\\Control\\Remote Assistance")
    if not k: return _clean("Not found")
    items=["  {}: {}".format(n,d) for n,d in _rvals(k)]
    winreg.CloseKey(k)
    return _found("Remote Assistance settings present",items) if items else _clean("No data")
def n_network_list_mgr():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged")
    if not k: return _clean("Not found")
    sigs=[]
    for sig in _rsubs(k):
        sk=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\NetworkList\\Signatures\\Unmanaged\\"+sig)
        if sk:
            name=next((d for n,d in _rvals(sk) if n=="Description" and isinstance(d,str)),sig)
            sigs.append("  "+name)
            winreg.CloseKey(sk)
    winreg.CloseKey(k)
    return _found("{} network signature(s) -- unique network fingerprints".format(len(sigs)),sigs) if sigs else _clean("No signatures")
def n_ie_typed_urls():
    k=_ropen(winreg.HKEY_CURRENT_USER,"Software\\Microsoft\\Internet Explorer\\TypedURLs")
    if not k: return _clean("Not found")
    items=["  {}: {}".format(n,d) for n,d in _rvals(k) if isinstance(d,str) and d]
    winreg.CloseKey(k)
    return _found("{} IE/Edge typed URL(s)".format(len(items)),items) if items else _clean("Empty")
def n_personal_certs():
    try:
        import ctypes.wintypes
        CERT_SYSTEM_STORE_CURRENT_USER=0x00010000
        CERT_STORE_OPEN_EXISTING_FLAG=0x00004000
        crypt=ctypes.windll.crypt32
        store=crypt.CertOpenStore(10,0,0,CERT_SYSTEM_STORE_CURRENT_USER|CERT_STORE_OPEN_EXISTING_FLAG,"MY")
        if store:
            count=0; cert=None
            while True:
                cert=crypt.CertEnumCertificatesInStore(store,cert)
                if not cert: break
                count+=1
            crypt.CertCloseStore(store,0)
            if count>0: return _found("{} personal certificate(s) in store".format(count),["  {} certificate(s) in My\\Personal store.".format(count),"  Contains identity certificates, code signing certs, client auth certs."])
    except: pass
    return _clean("No personal certificates or not accessible")
def n_google_drive():
    paths=[os.path.join(LOC(),"Google","DriveFS"),os.path.join(ROAM(),"Google","Drive"),os.path.join(USER(),"Google Drive")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        items=["  "+p for p in found]
        items.append("  Google Drive sync metadata -- records every synced/deleted file.")
        return _found("Google Drive data in {} location(s)".format(len(found)),items)
    return _clean("Not found")
def n_dropbox():
    paths=[os.path.join(ROAM(),"Dropbox"),os.path.join(LOC(),"Dropbox"),os.path.join(USER(),"Dropbox")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        items=["  "+p for p in found]+["  Dropbox metadata and sync history."]
        return _found("Dropbox data in {} location(s)".format(len(found)),items)
    return _clean("Not found")
def n_zoom_recordings():
    paths=[os.path.join(USER(),"Documents","Zoom"),os.path.join(USER(),"Zoom")]
    found=[p for p in paths if os.path.isdir(p)]
    if found:
        recs=[]
        for p in found: recs+=glob.glob(os.path.join(p,"**","*.mp4"),recursive=True)+glob.glob(os.path.join(p,"**","*.m4a"),recursive=True)
        items=["  "+p for p in found]+["  {} recording(s) found".format(len(recs))]
        return _found("Zoom recordings folder present",items)
    return _clean("Not found")
def n_wmi_persistence():
    wmi_file="C:\\Windows\\System32\\wbem\\Repository\\OBJECTS.DATA"
    if os.path.exists(wmi_file): return _found("WMI OBJECTS.DATA -- "+_sz(wmi_file),["  Path: "+wmi_file,"  Size: "+_sz(wmi_file),"  Contains WMI class definitions and event subscriptions.","  WMI subscriptions are a common malware persistence mechanism.","  Survives most standard cleanup tools."])
    return _clean("Not found")
def n_recents_automaticdests():
    jl2=os.path.join(ROAM(),"Microsoft","Windows","Recent","CustomDestinations")
    if os.path.isdir(jl2):
        files=os.listdir(jl2)
        if files: return _found("{} Custom Destinations jump list(s)".format(len(files)),["  "+f for f in sorted(files)[:20]]+["  Pinned/recent items per application."])
    return _clean("No custom destinations")
def n_indexer_vol():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SOFTWARE\\Microsoft\\Windows Search\\VolumeInfoCache")
    if not k: return _clean("Not found")
    vols=list(_rsubs(k)); winreg.CloseKey(k)
    if vols: return _found("{} volume(s) indexed by Windows Search".format(len(vols)),["  "+v for v in vols]+["  Indexed volumes have content searchable even after file deletion."])
    return _clean("No indexed volumes")
def n_lsa_secrets():
    k=_ropen(winreg.HKEY_LOCAL_MACHINE,"SECURITY\\Policy\\Secrets")
    if not k: return _ok(True,"LSA Secrets key exists (requires SYSTEM to read)",["  HKLM\\SECURITY\\Policy\\Secrets","  Contains cached domain credentials, service account passwords,","  browser saved passwords, auto-logon credentials.","  Accessible with SYSTEM privilege or from offline hive."])
    names=list(_rsubs(k)); winreg.CloseKey(k)
    return _found("{} LSA secret(s) present".format(len(names)),["  "+n for n in names]+["  Each entry may contain service account or cached credentials."])

# ============================================================================
# ARTIFACT REGISTRY -- 100 total
# ============================================================================
ARTIFACTS = [
  # --- HIGH (70) ---
  ("HIGH","AmCache Registry Hive",            "Every program run: name, path, SHA-1 hash, first/last timestamp",        s_amcache),
  ("HIGH","ShimCache / AppCompatCache",        "Every executable touched on disk, even if never run",                     s_shimcache),
  ("HIGH","Background Activity Monitor",       "Kernel-level execution timestamps per process, survives reboots",         s_bam),
  ("HIGH","SRUM Database",                     "Per-app network/CPU usage, 60 days back",                                  s_srum),
  ("HIGH","USB USBSTOR History",               "Serial numbers and names of every USB device ever connected",              s_usb),
  ("HIGH","Prefetch Execution Cache",          "Proof of execution with timestamps and file access patterns",              s_prefetch),
  ("HIGH","UserAssist Registry",               "Decoded app names with run counts and last-run timestamps",                s_userassist),
  ("HIGH","Shell Bags",                        "Every folder ever opened, including from removed drives",                  s_shellbags),
  ("HIGH","Volume Shadow Copies",              "OS snapshots: investigators recover deleted files from these",             s_vss),
  ("HIGH","Windows Search Index",              "Full-text index of documents including deleted ones",                      s_winsearch),
  ("HIGH","Windows Recall / CoreAI",           "AI screenshot store, semantic timeline of every screen",                  s_recall),
  ("HIGH","Windows Event Logs",                "System/Security/Application logs with detailed timestamps",               s_eventlogs),
  ("HIGH","RDP Connection History",            "Every Remote Desktop target ever connected to",                           s_rdp),
  ("HIGH","Saved WiFi Profiles",               "Every WiFi network ever connected, location timeline",                    s_wifi),
  ("HIGH","Windows Timeline (Activities)",     "Every app, file, website with timestamps across devices",                 s_timeline),
  ("HIGH","PowerShell Command History",        "Every PowerShell command typed, plain text",                              s_pshistory),
  ("HIGH","MountPoints2 Volume History",       "Every volume ever mounted on this machine",                               s_mountpoints),
  ("HIGH","Startup Run Keys",                  "Programs set to auto-run at login",                                       s_runkeys),
  ("HIGH","Installed Software Registry",       "Full list of all software ever installed",                                s_installed),
  ("HIGH","Remote Access Tool Logs",           "TeamViewer, AnyDesk, RustDesk connection logs",                           s_remote_tools),
  ("HIGH","MuiCache App Name Registry",        "Display name of every executed application -- cross-references execution",n_muicache),
  ("HIGH","OpenSave File Dialog MRU",          "Every file opened or saved through any Windows GUI dialog",               n_opensave),
  ("HIGH","LastVisited Folder Dialog MRU",     "Every folder navigated to via file open/save dialogs",                    n_lastvisited),
  ("HIGH","Network Profile History",           "Every network ever connected: name, category, first/last connect",        n_netprofiles),
  ("HIGH","Mapped Network Drives",             "Network shares mapped as drives -- reveals server/share targets",          n_mapped_drives),
  ("HIGH","LogonUI Last Logged-On User",       "Username of the last person who logged into this machine",                n_logonui),
  ("HIGH","NTUSER.DAT Registry Hive",          "User's entire registry hive -- every activity, preference, MRU",          n_ntuser_dat),
  ("HIGH","UsrClass.dat Shell Hive",           "Shell classes hive: thumbnails, Shell Bags, file type associations",       n_usrclass_dat),
  ("HIGH","SetupAPI Device Install Log",       "Every hardware device ever installed with timestamps and driver info",     n_setupapi),
  ("HIGH","WMI Repository Database",           "WMI event subscriptions -- primary malware persistence mechanism",         n_wmi_repo),
  ("HIGH","Microsoft Teams Data",              "Messages, files, call logs cached locally",                               n_teams),
  ("HIGH","Discord Data & Cache",              "Messages, media, guild data cached on disk",                              n_discord),
  ("HIGH","Signal Desktop Database",           "Encrypted Signal message database (SQLite + SQLCipher)",                  n_trace_desktop),
  ("HIGH","Telegram Desktop Data",             "Session keys and message cache in tdata folder",                          n_telegram),
  ("HIGH","WhatsApp Desktop Data",             "Local message database and media cache",                                  n_whatsapp),
  ("HIGH","Zoom Logs & Cache",                 "Meeting recordings, chat logs, crash reports",                            n_zoom),
  ("HIGH","Slack Workspace Data",              "All Slack messages and files cached locally",                             n_slack),
  ("HIGH","OneDrive Sync Data",                "Sync logs: metadata of all synced/deleted files",                         n_onedrive),
  ("HIGH","Windows.old Directory",             "Previous OS installation -- entire old user profile on disk",             n_windows_old),
  ("HIGH","Windows Installer Cache",           "Cached MSI/MSP of every installed program with file hashes",             n_win_installer),
  ("HIGH","Bluetooth Device History",          "Every Bluetooth device ever paired: MAC address and name",                n_bluetooth),
  ("HIGH","Windows Hello / NGC Keys",          "PIN, fingerprint, face authentication cryptographic keys",                n_ngc),
  ("HIGH","WSL Bash History",                  "Linux subsystem command history -- can hide forensic artifacts",           n_wsl),
  ("HIGH","Hyper-V Virtual Machines",          "VM configs -- separate forensic images may exist",                        n_hyperv),
  ("HIGH","VirtualBox VMs",                    "VirtualBox disk images and configs",                                      n_virtualbox),
  ("HIGH","VMware VMs",                        "VMware disk images and configs",                                          n_vmware),
  ("HIGH","Active Network Connections",        "Live connections at scan time: established sockets",                      n_active_connections),
  ("HIGH","ARP Cache",                         "Recently contacted IP/MAC address pairs",                                 n_arp_cache),
  ("HIGH","IE / Edge WebCache Database",       "ESE database of browsing history, cookies, downloaded files",             n_edge_webcache),
  ("HIGH","BITS Transfer Jobs",                "Background downloads -- used by Windows Update and malware",              n_bits_jobs),
  ("HIGH","Windows Biometric Database",        "Fingerprint and face recognition templates",                              n_biometric),
  ("HIGH","AppCompatFlags Registry",           "Manually applied compatibility shims -- evidence of specific program runs",n_appcompat_flags),
  ("HIGH","Kernel Memory Dump (MEMORY.DMP)",   "Full RAM at BSOD: encryption keys, process memory, network state",       n_memory_dmp),
  ("HIGH","System Volume Information",         "VSS snapshots + system restore points -- deleted file recovery",          n_sysvolinfo),
  ("HIGH","Delivery Optimization Cache",       "P2P Windows Update: records received files and peer IPs",                 n_delivery_opt),
  ("HIGH","Windows Update DataStore",          "Full update install history and pending downloads",                       n_win_update_ds),
  ("HIGH","Browser Extensions",               "Installed extension IDs: reveals tools, password managers, VPNs",         n_browser_ext),
  ("HIGH","Cortana / Search AI Data",          "Cortana queries, voice data, AI assistant interaction history",           n_cortana_data),
  ("HIGH","Microsoft Account Token Store",     "OAuth tokens linking this machine to Microsoft cloud identity",           n_ms_account),
  ("HIGH","UWP / AppX Store Apps",             "All Store app registrations -- reveals installed apps",                   n_appx_apps),
  ("HIGH","Startup Approved Items",            "Disabled startup entries -- evidence of attempted cleanup",               n_startup_approved),
  ("HIGH","Remote Assistance History",         "Helpdesk remote sessions -- who had remote access",                      n_remote_assist),
  ("HIGH","Network List Manager Signatures",   "Unique network fingerprints for every connected network",                 n_network_list_mgr),
  ("HIGH","IE TypedURLs Registry",             "URLs manually typed into IE/Edge address bar",                            n_ie_typed_urls),
  ("HIGH","Personal Certificate Store",        "Identity, code signing, client auth certificates",                       n_personal_certs),
  ("HIGH","Google Drive / DriveFS Data",       "Google Drive sync metadata -- every synced/deleted file recorded",        n_google_drive),
  ("HIGH","Dropbox Data & Cache",              "Dropbox metadata and sync history",                                       n_dropbox),
  ("HIGH","Zoom Meeting Recordings",           "Local meeting recordings (MP4/M4A) stored on disk",                      n_zoom_recordings),
  ("HIGH","Windows Search Volume Index",       "Volumes indexed -- content searchable even after file deletion",          n_indexer_vol),
  ("HIGH","LSA Secrets (Cached Credentials)",  "Cached domain creds, service passwords, auto-logon credentials",         n_lsa_secrets),
  # --- MEDIUM (20) ---
  ("MEDIUM","Recent Files (LNK)",              "Last accessed files, proves existence after deletion",                    s_recent),
  ("MEDIUM","Jump Lists",                      "Recently opened files per application",                                  s_jumplists),
  ("MEDIUM","Recent Documents MRU",            "Registry list of recently opened documents with filenames",              s_mru_docs),
  ("MEDIUM","Run Dialog MRU",                  "Commands typed into the Windows Run dialog",                             s_mru_run),
  ("MEDIUM","Typed Paths History",             "Paths typed into Explorer address bar",                                  s_typed_paths),
  ("MEDIUM","Explorer Search History",         "Search terms typed into Windows Explorer",                               s_searchhist),
  ("MEDIUM","Thumbnail Cache",                 "Thumbnails prove files existed even after deletion",                     s_thumbcache),
  ("MEDIUM","Browser History Files",           "Visited URLs, search terms, downloads across all browsers",             s_browsers),
  ("MEDIUM","Windows Error Reports",           "Crash reports revealing running processes and memory",                   s_wer),
  ("MEDIUM","Minidump Crash Files",            "Process memory snapshots at crash time",                                 s_crashdumps),
  ("MEDIUM","Shortcut (LNK) Files",            "File access history with MAC timestamps and volume serials",             s_lnk),
  ("MEDIUM","Clipboard History",               "Clipboard contents: copied text, images, file paths",                   s_clipboard),
  ("MEDIUM","Sticky Notes Database",           "All sticky note content stored in SQLite",                              s_stickynotes),
  ("MEDIUM","Office Recent Files MRU",         "Every Office doc opened recently: full path recorded",                  s_office_mru),
  ("MEDIUM","Windows Notifications DB",        "App notification history: messages, alerts, banners",                   s_notifications),
  ("MEDIUM","Print Spooler",                   "Print job queue: documents sent to printer",                            s_print_spool),
  ("MEDIUM","DNS Cache",                       "Recently resolved domains: websites and services contacted",            s_dns),
  ("MEDIUM","Startup Folder Items",            "Programs auto-launched at login via Startup folders",                   s_startup_folder),
  ("MEDIUM","Network Interface History",       "IP addresses, DHCP servers, and domains used on this machine",          s_netinterfaces),
  ("MEDIUM","Windows Defender History",        "Malware detections, quarantine records, scan logs",                     s_defender),
  # --- LOW (10) ---
  ("LOW","Temporary Files",                    "Residual working data from applications",                                s_temp),
  ("LOW","Recycle Bin Contents",               "Deleted files pending permanent removal",                                s_recycle),
  ("LOW","Icon Cache Database",                "Proof files were present on this system",                                s_iconcache),
  ("LOW","Pagefile.sys",                       "RAM overflow: decrypted data, keys, process memory",                     s_pagefile),
  ("LOW","Hibernation File",                   "Full compressed RAM dump, gigabytes of recoverable data",                s_hiberfil),
  ("LOW","Downloads Folder",                   "Downloaded files: evidence of internet activity",                        s_downloads),
  ("LOW","Scheduled Tasks",                    "Automated tasks: persistence mechanisms and admin scripts",               s_scheduled_tasks),
  ("LOW","Hosts File Modifications",           "Custom DNS overrides: possible DNS hijack or tracker blocking",          s_hosts_file),
  ("LOW","Windows Update Logs",                "Update and component installation history",                               s_winsupdate),
  ("LOW","Credential Manager",                 "Stored passwords and login tokens for websites and apps",                 s_credmanager),
]

assert len(ARTIFACTS)==100,"Expected 100 artifacts, got {}".format(len(ARTIFACTS))
WEIGHT={"HIGH":3,"MEDIUM":2,"LOW":1}

# ============================================================================
# PDF GENERATION
# ============================================================================
def _ensure_reportlab():
    try:
        import reportlab; return True
    except ImportError:
        print("  Installing PDF library (reportlab)...")
        try:
            subprocess.check_call([sys.executable,"-m","pip","install","reportlab","--quiet"],creationflags=subprocess.CREATE_NO_WINDOW)
            return True
        except Exception as e:
            print("  Failed: "+str(e)); return False

def generate_pdf(all_results, path):
    if not _ensure_reportlab():
        print("  PDF generation skipped -- reportlab not available."); return
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
        from reportlab.lib.colors import HexColor, white, black, Color
        from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, HRFlowable, PageBreak
        from reportlab.lib.units import cm
        from reportlab.lib.enums import TA_CENTER, TA_LEFT, TA_RIGHT
        from reportlab.platypus import KeepTogether
    except Exception as e:
        print("  PDF import error: "+str(e)); return

    C_BG    = HexColor("#0f0f0f")
    C_CARD  = HexColor("#1a1a1a")
    C_OR    = HexColor("#f97316")
    C_RED   = HexColor("#ef4444")
    C_AMB   = HexColor("#f59e0b")
    C_GRN   = HexColor("#22c55e")
    C_TEXT  = HexColor("#e2e8f0")
    C_MUTED = HexColor("#64748b")
    C_BLU   = HexColor("#60a5fa")
    C_BORD  = HexColor("#2a2a2a")
    C_H_ROW = HexColor("#1e1e1e")

    exposed=[r for r in all_results if r["result"]["exposed"]]
    h=[r for r in exposed if r["tier"]=="HIGH"]
    m=[r for r in exposed if r["tier"]=="MEDIUM"]
    l=[r for r in exposed if r["tier"]=="LOW"]
    ms=sum(WEIGHT[t] for t,*_ in ARTIFACTS)
    gs=sum(WEIGHT[r["tier"]] for r in exposed)
    score=round((gs/ms)*100)
    lbl="HIGH EXPOSURE" if score>=61 else ("MEDIUM EXPOSURE" if score>=31 else "LOW EXPOSURE")
    sc=C_RED if score>=61 else (C_AMB if score>=31 else C_GRN)
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    hostname=""
    try: import socket; hostname=socket.gethostname()
    except: pass

    doc=SimpleDocTemplate(path,pagesize=A4,
        leftMargin=1.5*cm,rightMargin=1.5*cm,topMargin=0.6*cm,bottomMargin=2*cm)

    styles=getSampleStyleSheet()
    def sty(name,**kw):
        return ParagraphStyle(name,**kw)

    st_title = sty("title",fontSize=28,textColor=C_OR,    fontName="Helvetica-Bold",spaceAfter=4,alignment=TA_CENTER)
    st_sub   = sty("sub",  fontSize=11,textColor=C_MUTED, fontName="Helvetica",     spaceAfter=2,alignment=TA_CENTER)
    st_score = sty("score",fontSize=52,textColor=sc,       fontName="Helvetica-Bold",spaceAfter=2,alignment=TA_CENTER)
    st_slbl  = sty("slbl", fontSize=14,textColor=sc,       fontName="Helvetica-Bold",spaceAfter=8,alignment=TA_CENTER)
    st_h2    = sty("h2",   fontSize=13,textColor=C_OR,    fontName="Helvetica-Bold",spaceBefore=12,spaceAfter=4)
    st_body  = sty("body", fontSize=8.5,textColor=C_TEXT, fontName="Helvetica",     spaceAfter=2,leading=12)
    st_small = sty("small",fontSize=7.5,textColor=C_MUTED,fontName="Helvetica",     spaceAfter=1,leading=10)
    st_found = sty("found",fontSize=7.5,textColor=C_TEXT, fontName="Courier",       spaceAfter=1,leading=10)
    st_tier  = sty("tier", fontSize=8,  textColor=white,  fontName="Helvetica-Bold",alignment=TA_CENTER)
    st_link  = sty("link", fontSize=8,  textColor=C_BLU,  fontName="Helvetica",     spaceAfter=1)
    st_foot  = sty("foot", fontSize=8,  textColor=C_MUTED,fontName="Helvetica",     alignment=TA_CENTER)

    story=[]

    # ---- Cover page ----
    story.append(Spacer(1,0.15*cm))
    story.append(Paragraph("TRACE 1.0",
        sty("titleX",fontSize=40,textColor=C_OR,fontName="Helvetica-Bold",spaceAfter=0,alignment=TA_CENTER)))
    story.append(Spacer(1,1.75*cm))
    story.append(Paragraph(
        "<font color='#94a3b8'>T</font><font color='#e2e8f0'>otal &nbsp; </font>"
        "<font color='#94a3b8'>R</font><font color='#e2e8f0'>isk &nbsp; </font>"
        "<font color='#94a3b8'>A</font><font color='#e2e8f0'>ssessment &nbsp; </font>"
        "<font color='#94a3b8'>C</font><font color='#e2e8f0'>omputed &nbsp; </font>"
        "<font color='#94a3b8'>E</font><font color='#e2e8f0'>xposure</font>",
        sty("abbr",fontSize=11,textColor=C_TEXT,fontName="Helvetica",spaceAfter=0,alignment=TA_CENTER,leading=14)))
    story.append(Spacer(1,3.5*cm))
    story.append(Spacer(1,0.2*cm))
    story.append(Paragraph("Forensic Exposure Scanner – 100-Artifact Edition",
        sty("sub1",fontSize=11,textColor=C_MUTED,fontName="Helvetica",spaceAfter=4,alignment=TA_CENTER)))
    story.append(Paragraph("Windows Anti-Forensics Risk Assessment",
        sty("sub2",fontSize=10,textColor=C_MUTED,fontName="Helvetica",spaceAfter=0,alignment=TA_CENTER)))
    story.append(Spacer(1,0.6*cm))
    story.append(HRFlowable(width="100%",thickness=2,color=C_OR,spaceAfter=0))
    story.append(Spacer(1,0.6*cm))
    story.append(Paragraph(str(score)+"/100",
        sty("scoreX",fontSize=48,textColor=sc,fontName="Helvetica-Bold",spaceAfter=0,alignment=TA_CENTER,leading=54)))
    story.append(Spacer(1,0.2*cm))
    story.append(Paragraph(lbl,
        sty("slblX",fontSize=13,textColor=sc,fontName="Helvetica-Bold",spaceAfter=0,alignment=TA_CENTER)))
    story.append(Spacer(1,0.5*cm))

    # Tier summary table
    tier_data=[
        [Paragraph("HIGH",sty("tH",fontSize=10,textColor=white,fontName="Helvetica-Bold",alignment=TA_CENTER)),
         Paragraph("MEDIUM",sty("tM",fontSize=10,textColor=white,fontName="Helvetica-Bold",alignment=TA_CENTER)),
         Paragraph("LOW",sty("tL",fontSize=10,textColor=white,fontName="Helvetica-Bold",alignment=TA_CENTER))],
        [Paragraph("{}/{}".format(len(h),sum(1 for t,*_ in ARTIFACTS if t=="HIGH")),   sty("vH",fontSize=18,textColor=C_RED,fontName="Helvetica-Bold",alignment=TA_CENTER)),
         Paragraph("{}/{}".format(len(m),sum(1 for t,*_ in ARTIFACTS if t=="MEDIUM")), sty("vM",fontSize=18,textColor=C_AMB,fontName="Helvetica-Bold",alignment=TA_CENTER)),
         Paragraph("{}/{}".format(len(l),sum(1 for t,*_ in ARTIFACTS if t=="LOW")),    sty("vL",fontSize=18,textColor=C_GRN,fontName="Helvetica-Bold",alignment=TA_CENTER))],
    ]
    tt=Table(tier_data,colWidths=[5.5*cm,5.5*cm,5.5*cm])
    tt.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(0,1),C_RED),
        ("BACKGROUND",(1,0),(1,1),HexColor("#78350f")),
        ("BACKGROUND",(2,0),(2,1),HexColor("#14532d")),
        ("BACKGROUND",(0,1),(0,1),HexColor("#1a0a0a")),
        ("BACKGROUND",(1,1),(1,1),HexColor("#1a1100")),
        ("BACKGROUND",(2,1),(2,1),HexColor("#001a08")),
        ("BOX",(0,0),(-1,-1),1,C_BORD),
        ("INNERGRID",(0,0),(-1,-1),0.5,C_BORD),
        ("TOPPADDING",(0,0),(-1,-1),8),
        ("BOTTOMPADDING",(0,0),(-1,-1),8),
    ]))
    story.append(tt)
    story.append(Spacer(1,0.6*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORD,spaceAfter=8))

    meta=[
        ["Scan Date:",now],
        ["Machine:",hostname],
        ["User:",os.environ.get("USERNAME","unknown")],
        ["Author:",AUTHOR+"  |  "+TITLE],
        ["Email :",EMAIL],
        ["REDACT:",REDACT],
        ["AAD-50:",AAD50],
    ]
    for row in meta:
        story.append(Paragraph("<b><font color='#64748b'>{}  </font></b><font color='#e2e8f0'>{}</font>".format(row[0],row[1]),
            sty("meta",fontSize=9,fontName="Helvetica",spaceAfter=3,textColor=C_TEXT)))
    story.append(Spacer(1,0.4*cm))
    story.append(HRFlowable(width="100%",thickness=1,color=C_OR,spaceAfter=12))
    story.append(PageBreak())

    # ---- Findings table ----
    story.append(Paragraph("Detailed Findings",st_h2))
    story.append(Spacer(1,0.2*cm))

    # Table header
    col_w=[1.6*cm,5.8*cm,5.0*cm,5.0*cm]
    hdr_row=[Paragraph("TIER",st_tier),Paragraph("ARTIFACT",st_tier),Paragraph("STATUS",st_tier),Paragraph("DETAIL",st_tier)]
    rows=[hdr_row]
    for r in all_results:
        tc_map={"HIGH":C_RED,"MEDIUM":C_AMB,"LOW":C_GRN}
        t_col=tc_map.get(r["tier"],C_MUTED)
        status_col=C_RED if r["result"]["exposed"] else C_GRN
        status_txt="EXPOSED" if r["result"]["exposed"] else "CLEAN"
        rows.append([
            Paragraph(r["tier"],sty("tc",fontSize=7,textColor=t_col,fontName="Helvetica-Bold",alignment=TA_CENTER)),
            Paragraph(r["name"],sty("tn",fontSize=8,textColor=C_TEXT if r["result"]["exposed"] else C_MUTED,fontName="Helvetica-Bold" if r["result"]["exposed"] else "Helvetica")),
            Paragraph(status_txt,sty("ts",fontSize=8,textColor=status_col,fontName="Helvetica-Bold",alignment=TA_CENTER)),
            Paragraph(r["result"]["summary"][:80],sty("td",fontSize=7.5,textColor=C_TEXT if r["result"]["exposed"] else C_MUTED,fontName="Helvetica")),
        ])

    tbl=Table(rows,colWidths=col_w,repeatRows=1)
    tbl.setStyle(TableStyle([
        ("BACKGROUND",(0,0),(-1,0),C_OR),
        ("TEXTCOLOR",(0,0),(-1,0),white),
        ("FONTNAME",(0,0),(-1,0),"Helvetica-Bold"),
        ("FONTSIZE",(0,0),(-1,0),9),
        ("TOPPADDING",(0,0),(-1,-1),4),
        ("BOTTOMPADDING",(0,0),(-1,-1),4),
        ("LEFTPADDING",(0,0),(-1,-1),4),
        ("RIGHTPADDING",(0,0),(-1,-1),4),
        ("BOX",(0,0),(-1,-1),0.5,C_BORD),
        ("INNERGRID",(0,0),(-1,-1),0.3,C_BORD),
        ("ROWBACKGROUNDS",(0,1),(-1,-1),[HexColor("#111111"),HexColor("#1a1a1a")]),
        ("ALIGN",(2,0),(2,-1),"CENTER"),
    ]))
    # Highlight exposed rows red-tinted
    for i,r in enumerate(all_results,1):
        if r["result"]["exposed"]:
            tbl.setStyle(TableStyle([("BACKGROUND",(0,i),(-1,i),HexColor("#1a0a0a") if r["tier"]=="HIGH" else (HexColor("#1a1300") if r["tier"]=="MEDIUM" else HexColor("#0a1a0a")))]))
    story.append(tbl)
    story.append(PageBreak())

    # ---- Detailed items per exposed artifact ----
    story.append(Paragraph("Exposed Artifact Details",st_h2))
    story.append(Spacer(1,0.2*cm))

    tc_map={"HIGH":C_RED,"MEDIUM":C_AMB,"LOW":C_GRN}
    for r in all_results:
        if not r["result"]["exposed"]: continue
        t_col=tc_map.get(r["tier"],C_MUTED)
        block=[]
        block.append(Paragraph("<b>[{}]  {}</b>".format(r["tier"],r["name"]),
            sty("ah",fontSize=10,textColor=t_col,fontName="Helvetica-Bold",spaceBefore=8,spaceAfter=2)))
        block.append(Paragraph(r["note"],
            sty("an",fontSize=8,textColor=C_MUTED,fontName="Helvetica-Oblique",spaceAfter=2)))
        block.append(Paragraph("Status: EXPOSED  --  {}".format(r["result"]["summary"]),
            sty("as",fontSize=8.5,textColor=C_RED,fontName="Helvetica-Bold",spaceAfter=3)))
        if r["result"].get("items"):
            for item in r["result"]["items"][:20]:
                block.append(Paragraph(item.strip(),st_found))
            if len(r["result"]["items"])>20:
                block.append(Paragraph("... and {} more items".format(len(r["result"]["items"])-20),st_small))
        block.append(HRFlowable(width="100%",thickness=0.3,color=C_BORD,spaceAfter=4))
        story.append(KeepTogether(block[:8]))
        for b in block[8:]: story.append(b)

    REDACT_SF = "https://sourceforge.net/projects/redact"

    # ---- Footer page ----
    story.append(PageBreak())
    story.append(Spacer(1,1.5*cm))
    story.append(HRFlowable(width="100%",thickness=2,color=C_OR,spaceAfter=12))
    story.append(Paragraph("TRACE 1.0 &mdash; Total Risk Assessment &amp; Computed Exposure",
        sty("f1",fontSize=13,textColor=C_OR,fontName="Helvetica-Bold",alignment=TA_CENTER,spaceAfter=4)))
    story.append(Paragraph("100-Artifact Edition &nbsp;|&nbsp; Windows Anti-Forensics Risk Assessment",
        sty("f2",fontSize=9,textColor=C_MUTED,fontName="Helvetica",alignment=TA_CENTER,spaceAfter=6)))
    story.append(HRFlowable(width="100%",thickness=0.5,color=C_BORD,spaceAfter=14))

    # About REDACT box
    story.append(Paragraph("About REDACT",
        sty("ah2",fontSize=11,textColor=C_OR,fontName="Helvetica-Bold",spaceAfter=4)))
    story.append(Paragraph(
        "<b>REDACT 3.3.0</b> is a Windows privacy and anti-forensics tool that detects and permanently "
        "wipes <b>255+ forensic artifact categories</b> from your system &mdash; including registry hives, "
        "event logs, prefetch, BAM, SRUM, browser history, USB history, shellbags, LNK files, jump lists, "
        "thumbnail caches, and much more. REDACT uses secure overwrite passes to ensure artifacts cannot "
        "be recovered by investigators or forensic tools. Designed for Windows 10/11, no installation required.",
        sty("fd",fontSize=9,textColor=C_TEXT,fontName="Helvetica",spaceAfter=6,leading=14)))
    story.append(Paragraph(
        "Download REDACT on <b><a href='{}' color='#60a5fa'>GitHub</a></b> &nbsp;|&nbsp; "
        "<b><a href='{}' color='#60a5fa'>SourceForge</a></b>".format(REDACT, REDACT_SF),
        sty("fl",fontSize=9,textColor=C_BLU,fontName="Helvetica",spaceAfter=14)))
    story.append(HRFlowable(width="100%",thickness=0.5,color=C_BORD,spaceAfter=14))

    # About AAD-50 box
    story.append(Paragraph("About AAD-50",
        sty("ah3",fontSize=11,textColor=C_OR,fontName="Helvetica-Bold",spaceAfter=4)))
    story.append(Paragraph(
        "<b>AAD-50</b> (linux-nvme PR #3438) is a Linux NVMe driver improvement authored by Yonas Abeselom, "
        "merged June 16 2026. The patch addresses a 50-command queue depth optimization in the "
        "<b>nvme-cli</b> toolchain, improving NVMe SSD performance and reliability under high I/O workloads "
        "on Linux systems. The PR was reviewed and merged into the official linux-nvme/nvme-cli repository.",
        sty("fd2",fontSize=9,textColor=C_TEXT,fontName="Helvetica",spaceAfter=6,leading=14)))
    story.append(Paragraph(
        "View AAD-50 on <b><a href='{}' color='#60a5fa'>GitHub</a></b> &nbsp;|&nbsp; <b><a href='{}' color='#60a5fa'>SourceForge</a></b>".format(AAD50, AAD50_SF),
        sty("fl2",fontSize=9,textColor=C_BLU,fontName="Helvetica",spaceAfter=14)))
    story.append(HRFlowable(width="100%",thickness=0.5,color=C_BORD,spaceAfter=14))

    story.append(Spacer(1,0.4*cm))
    story.append(HRFlowable(width="100%",thickness=2,color=C_OR,spaceAfter=8))
    story.append(Paragraph("By {}  &nbsp;|&nbsp;  {}  &nbsp;|&nbsp;  {}".format(AUTHOR,TITLE,EMAIL),
        sty("fc",fontSize=9,textColor=C_TEXT,fontName="Helvetica",alignment=TA_CENTER,spaceAfter=4)))
    story.append(HRFlowable(width="100%",thickness=1,color=C_BORD))

    def cover_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0,0,A4[0],A4[1],fill=1,stroke=0)
        canvas.restoreState()

    def page_bg(canvas, doc):
        canvas.saveState()
        canvas.setFillColor(C_BG)
        canvas.rect(0,0,A4[0],A4[1],fill=1,stroke=0)
        canvas.setFillColor(C_MUTED)
        canvas.setFont("Helvetica",7)
        canvas.drawCentredString(A4[0]/2,1.2*cm,"TRACE 1.0  |  {}  |  {}  |  Page {}".format(AUTHOR,EMAIL,doc.page-1))
        canvas.restoreState()

    doc.build(story,onFirstPage=cover_bg,onLaterPages=page_bg)
    print()
    print(G+BO+"  PDF saved: "+path+RS)

# ============================================================================
# TERMINAL OUTPUT
# ============================================================================
def print_result(tier,name,note,result):
    tc=TC.get(tier,W)
    stat=R+BO+"EXPOSED"+RS if result["exposed"] else G+"CLEAN  "+RS
    print(SEP)
    print("{}{}[{:<6}]{}  {}{}{}".format(tc,BO,tier,RS,W,BO,name)+RS)
    print("          {}Investigator: {}{}".format(DI,note,RS))
    print("  Status  : {}  {}".format(stat,result["summary"]))
    if result["exposed"] and result.get("items"):
        print("  Found   :")
        for line in result["items"]: print(line)
    print()

def print_summary(all_results):
    exposed=[r for r in all_results if r["result"]["exposed"]]
    h=[r for r in exposed if r["tier"]=="HIGH"]
    m=[r for r in exposed if r["tier"]=="MEDIUM"]
    l=[r for r in exposed if r["tier"]=="LOW"]
    ms=sum(WEIGHT[t] for t,*_ in ARTIFACTS)
    gs=sum(WEIGHT[r["tier"]] for r in exposed)
    score=round((gs/ms)*100)
    sc,lbl=(R,"HIGH EXPOSURE") if score>=61 else (Y,"MEDIUM EXPOSURE") if score>=31 else (G,"LOW EXPOSURE")
    print(); print(OR+BO+SEP2+RS)
    print(OR+BO+"  FORENSIC EXPOSURE SCORE : {}/100  --  {}".format(score,lbl)+RS)
    print(OR+BO+SEP2+RS); print()
    print("  "+R+BO+"HIGH   exposed : {:>2} / {}".format(len(h),sum(1 for t,*_ in ARTIFACTS if t=="HIGH"))+RS)
    print("  "+Y+BO+"MEDIUM exposed : {:>2} / {}".format(len(m),sum(1 for t,*_ in ARTIFACTS if t=="MEDIUM"))+RS)
    print("  "+G+BO+"LOW    exposed : {:>2} / {}".format(len(l),sum(1 for t,*_ in ARTIFACTS if t=="LOW"))+RS)
    print("  "+W+"Total  exposed : {:>2} / {}".format(len(exposed),len(ARTIFACTS))+RS); print()
    print("  "+DI+"By {} | {} | {}".format(AUTHOR,EMAIL,REDACT)+RS); print()
    for color,label,bucket in [(R,"HIGH -- Critical",h),(Y,"MEDIUM -- Significant",m),(G,"LOW -- Minor",l)]:
        if bucket:
            print("  "+color+BO+label+":"+RS)
            for r in bucket: print("    * "+r["name"])
            print()

def save_txt(all_results,path):
    exposed=[r for r in all_results if r["result"]["exposed"]]
    h=[r for r in exposed if r["tier"]=="HIGH"]
    m=[r for r in exposed if r["tier"]=="MEDIUM"]
    l=[r for r in exposed if r["tier"]=="LOW"]
    ms=sum(WEIGHT[t] for t,*_ in ARTIFACTS)
    gs=sum(WEIGHT[r["tier"]] for r in exposed)
    score=round((gs/ms)*100)
    label="HIGH" if score>=61 else ("MEDIUM" if score>=31 else "LOW")
    now=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    lines=["="*78,"  TRACE 1.0 -- Forensic Exposure Scanner (100-Artifact Edition)","  By {} | {} | {}".format(AUTHOR,TITLE,EMAIL),"  REDACT: {}".format(REDACT),"  AAD-50: {}".format(AAD50),"  Report: "+now,"="*78,"","  FORENSIC EXPOSURE SCORE : {}/100  --  {} EXPOSURE".format(score,label),"","  HIGH   exposed: {:>2} / {}".format(len(h),sum(1 for t,*_ in ARTIFACTS if t=="HIGH")),"  MEDIUM exposed: {:>2} / {}".format(len(m),sum(1 for t,*_ in ARTIFACTS if t=="MEDIUM")),"  LOW    exposed: {:>2} / {}".format(len(l),sum(1 for t,*_ in ARTIFACTS if t=="LOW")),"  Total  exposed: {:>2} / {}".format(len(exposed),len(ARTIFACTS)),"","-"*78,"  DETAILED FINDINGS","-"*78,""]
    for r in all_results:
        lines.append("[{:<6}]  {}".format(r["tier"],r["name"]))
        lines.append("         Note  : "+r["note"])
        lines.append("         Status: {}  --  {}".format("EXPOSED" if r["result"]["exposed"] else "CLEAN",r["result"]["summary"]))
        if r["result"]["exposed"] and r["result"].get("items"):
            lines.append("         Found :")
            for item in r["result"]["items"]: lines.append("         "+item)
        lines.append("")
    lines+=["="*78,"  TRACE 1.0 | By {} | {}".format(AUTHOR,EMAIL),"  REDACT 3.3.0: {}".format(REDACT),"  AAD-50 PR#3438: {}".format(AAD50),"="*78]
    with open(path,"w",encoding="utf-8") as fh: fh.write("\n".join(lines))
    print(G+BO+"  TXT saved: "+path+RS)

# ============================================================================
# ENTRY POINT
# ============================================================================
if __name__=="__main__":
    args=sys.argv[1:]
    output_path=None
    if "--output" in args:
        idx=args.index("--output")
        if idx+1<len(args): output_path=args[idx+1]
    if "--help" in args or "-h" in args:
        print(W+BO+"TRACE 1.0 -- 100-Artifact Forensic Exposure Scanner"+RS)
        print(DI+"  Usage: python TRACE100.py [--output path]"+RS)
        sys.exit()

    print()
    print(OR+BO+"  "+"="*74+RS)
    print(OR+BO+"  TRACE 1.0 -- Forensic Exposure Scanner (100-Artifact Edition)"+RS)
    print(OR+BO+"  By {} | {} | {}".format(AUTHOR,TITLE,EMAIL)+RS)
    print(OR+BO+"  REDACT  : "+REDACT+RS)
    print(OR+BO+"  AAD-50  : "+AAD50+" | SF: "+AAD50_SF+RS)
    print(OR+BO+"  "+"="*74+RS)
    print()
    print(W+"  Scanning {} artifact categories across your system...".format(len(ARTIFACTS))+RS)
    print(DI+"  Elevated privileges confirmed. Starting deep scan."+RS); print()

    all_results=[]
    for tier,name,note,fn in ARTIFACTS:
        print("  "+DI+"[...] Scanning: {}".format(name)+RS,end="\r")
        try: result=fn()
        except Exception as exc:
            result=_ok(False,"Error: {}".format(exc))
        print_result(tier,name,note,result)
        all_results.append({"tier":tier,"name":name,"note":note,"result":result})

    print_summary(all_results)

    # --- Save prompt ---
    print(SEP)
    print(W+BO+"  Save report?"+RS)
    print("  [Y] Save TXT + PDF report to Desktop")
    print("  [N] Exit without saving"); print()
    try: choice=input("  Your choice (Y/N): ").strip().upper()
    except: choice="N"

    if choice=="Y":
        desktop=os.path.join(USER(),"Desktop")
        ts=datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        txt_path=os.path.join(desktop,"TRACE_Report_{}.txt".format(ts))
        pdf_path=os.path.join(desktop,"TRACE_Report_{}.pdf".format(ts))
        print()
        print(W+"  Saving TXT report..."+RS)
        save_txt(all_results,txt_path)
        print(W+"  Generating PDF report..."+RS)
        generate_pdf(all_results,pdf_path)
        print()
        print(OR+BO+"  Reports saved to Desktop:"+RS)
        print(W+"  - "+os.path.basename(txt_path)+RS)
        print(W+"  - "+os.path.basename(pdf_path)+RS)
    else:
        print(W+"  Exiting without saving."+RS)

    print()
    input("  Press Enter to exit...")
