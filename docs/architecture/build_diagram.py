"""Rebuild the self-contained architecture SVG from publisher-supplied assets."""
from pathlib import Path
from html import escape
import base64, json
D=Path(__file__).resolve().parent
assets=json.loads((D/'assets/sources.json').read_text())
p=[]
def add(s):p.append(s)
def text(x,y,s,size=23,weight=400,color='#34383d',anchor='start'):
 add(f'<text x="{x}" y="{y}" font-size="{size}" font-weight="{weight}" fill="{color}" text-anchor="{anchor}">{escape(s)}</text>')
def rect(x,y,w,h,r=18,fill='white',stroke='#cbd0d5',sw=2):
 add(f'<rect x="{x}" y="{y}" width="{w}" height="{h}" rx="{r}" fill="{fill}" stroke="{stroke}" stroke-width="{sw}"/>')
def line(d,dash=False,arrow=True):
 add(f'<path d="{d}" fill="none" stroke="{ "#989fa7" if dash else "#24282d"}" stroke-width="{2 if dash else 3}" stroke-linecap="round" stroke-linejoin="round"'+(' stroke-dasharray="7 8"' if dash else '')+(' marker-end="url(#arrow)"' if arrow else '')+'/>')
def icon(k,x,y,w=58,h=58):
 a=assets[k];f=D/'assets'/a['file'];mime={'svg':'image/svg+xml','png':'image/png','jpg':'image/jpeg'}[f.suffix[1:]]
 if k=='fastapi':rect(x,y,w,h,w/2,'#009688','none',0)
 b64=base64.b64encode(f.read_bytes()).decode()
 add(f'<image x="{x}" y="{y}" width="{w}" height="{h}" preserveAspectRatio="xMidYMid meet" href="data:{mime};base64,{b64}"><title>{escape(k+" — "+a["url"])}</title></image>')
def tool(k,x,y,label,w=62):
 icon(k,x,y,w,60);text(x+w/2,y+86,label,19,600,anchor='middle')
def panel(x,y,w,h,n,title,m):
 rect(x,y,w,h)
 if n:
  rect(x+24,y+24,44,38,10,'#25292e','#25292e',0);text(x+46,y+51,n,22,650,'white','middle')
 text(x+(84 if n else 32),y+53,title,29,650,'#20252a')
 text(x+w-24,y+50,m,18,600,'#6d747c','end')
 add(f'<path d="M{x+24} {y+80}H{x+w-24}" stroke="#e1e4e8"/>')
# v2: agent roles and the distinction between current/default and deep modes are explicit.
add('<svg xmlns="http://www.w3.org/2000/svg" xmlns:xlink="http://www.w3.org/1999/xlink" width="2600" height="1800" viewBox="0 0 2600 1800" role="img" aria-labelledby="title desc">')
add('<title id="title">Software Supply Chain Guardian — architecture and agent roles</title><desc id="desc">Repository triggers feed deterministic discovery, detection and contextual scoring. The default workflow contains Lead, parallel Investigators, Verifier and Fixer, with a code Gatekeeper. A person approves an exact patch before Docker validation. Results reach the React dashboard, Electron Buddy, GitHub and reports. Separate modules show the legacy deep-mode specialist team and human-approved Scoring Advisor. All ten M0–M9 milestones are mapped.</desc>')
add('<defs><marker id="arrow" markerWidth="12" markerHeight="12" refX="10" refY="5" orient="auto" markerUnits="userSpaceOnUse"><path d="M0 0L10 5L0 10" fill="none" stroke="#24282d" stroke-width="2"/></marker></defs>')
add('<g font-family="Arial, Helvetica, sans-serif"><rect width="2600" height="1800" fill="white"/>')
text(80,54,'BOSCH BGSW  /  ARCHITECTURE OF THE IMPLEMENTED SOLUTION',18,650,'#68717b')
text(80,112,'Software Supply Chain Guardian',48,700,'#20252a')
text(80,156,'Detect risky dependencies and suspicious changes → explain the evidence → validate a human-approved fix.',25,400,'#59636d')
text(2520,53,'24 NOVEMBER 2026',18,600,'#68717b','end')
# 1–2: intake, fact collection and risk reasoning.
panel(80,210,550,280,'01','Repository & triggers','M8')
icon('github',111,310,62,62)
text(198,331,'GitHub PR / nightly scan',25,600)
text(198,364,'Actions → self-hosted runner',22)
text(112,417,'Queue → fetch and verify base / head SHAs',22)
text(112,458,'Also: dashboard / CLI · Git URL · ZIP · local repo',20)
panel(730,210,1050,280,'02','Discover & detect','M1 · M2')
for k,x,l,w in [('syft',771,'Syft',100),('osv',950,'OSV.dev',90),('grype',1115,'Grype',104),('zizmor',1305,'zizmor',60)]:tool(k,x,310,l,w)
text(1448,337,'Base vs head',24,650)
text(1448,376,'introduced / existing / fixed',19)
text(764,430,'SBOMs + dependency graph · vulnerabilities · 14 supply-chain detectors · CI / image checks',22)
text(764,465,'Scans read source files; project code does not run during analysis.',21,400,'#68717b')
panel(1880,210,640,280,'','Contextual risk','M2')
text(1912,332,'Hard floors → SSVC → AHP priority',25,600)
text(1912,374,'KEV · EPSS · exposure · static imports',22)
text(1912,416,'Confidence + rank stability + ranked fixes',21)
rect(1909,437,582,37,8,'#f4f5f6','none',0)
text(1924,463,'ALLOW / REVIEW / BLOCK + completion state',20,650)
line('M630 350H730');text(680,325,'Commit',18,500,anchor='middle')
line('M1780 350H1880');text(1830,325,'Findings',17,500,anchor='middle')
line('M2200 490V518H1380V560')
text(1725,544,'Scored findings + stored evidence packets',20,500,anchor='middle')
# 3: a visible agent lane using the same role symbols as the application.
rect(80,560,2440,340,18,'white','#9aa2ab',2)
rect(104,584,44,38,10,'#25292e','#25292e',0);text(126,611,'03',22,650,'white','middle')
text(164,613,'Agent workflow',30,650,'#20252a')
text(475,612,'Four product roles; Lead is rule-based. Gatekeeper is code.',22,400,'#68717b')
text(1715,610,'M3 · M4',18,600,'#68717b')
icon('deepseek',1932,578,55,44);text(2001,607,'DeepSeek',22,600)
icon('gemini',2170,578,45,44);text(2230,607,'Gemini fallback',21,600)
roles=[
 (110,'agent-ShieldStar','Lead','RULES COORDINATOR',['Groups introduced findings','into component cases; assigns','one Investigator per case.']),
 (600,'agent-Detective','Investigator × cases','AI · PARALLEL',['Reads diffs, lockfiles and','package evidence; tests the','strongest innocent explanation.']),
 (1090,'agent-Scales','Verifier','AI · INDEPENDENT REVIEW',['Challenges unsupported claims,','corroborates evidence and','identifies missed risks.']),
 (1580,'agent-Wrench','Fixer','AI REVIEW + COMPUTED PATCH',['Rules compute the exact fix.','AI explains trade-offs and concerns.','One combined patch + SHA-256.']),
 (2070,'agent-Gavel','Gatekeeper','CODE · CHECKS ALL AI OUTPUTS',['Checks evidence IDs and versions;','rejects unsupported claims.','AI cannot override the rules verdict.'])]
for x,k,name,kind,body in roles:
 rect(x,650,420,215,12,'#fafafa','#dce0e5',1)
 icon(k,x+18,668,47,47);text(x+79,701,name,25,650)
 text(x+20,743,kind,15,650,'#68717b')
 for j,s in enumerate(body):text(x+20,779+29*j,s,21)
 if x<2070:line(f'M{x+420} 754H{x+490}')
# Route the reviewed patch to human approval, away from the model nodes.
line('M2280 900V932H355V980')
text(1380,956,'Computed patch + checked AI review → a person decides',21,500,anchor='middle')
# 4–6: approval, controlled execution and user-facing outcomes.
panel(80,980,550,300,'04','Human approval','M5')
icon('agent-User',110,1080,50,50)
text(184,1100,'Review · approve / reject · accept risk',22,600)
text(112,1152,'Name + reason + expiry',24,600)
text(112,1192,'Bound to base, head, patch, policy and profile',21)
text(112,1240,'Changed patch or stale approval → nothing executes',20,400,'#68717b')
panel(730,980,1050,300,'05','Isolated validation','M5')
icon('docker',764,1081,78,53);text(859,1116,'Docker',22,600)
icon('verdaccio',1000,1080,51,53);text(1067,1116,'Verdaccio',22,600)
icon('syft',1285,1080,82,53);text(1391,1116,'Artifact SBOM',22,600)
text(764,1170,'Baseline vs candidate: install → build → security test → unit → integration',23,600)
text(764,1210,'Source rescan + artifact SBOM diff → deterministic verification gate',23)
text(764,1252,'Non-root · no secrets / Docker socket · restricted network · approval checked first',20,400,'#68717b')
panel(1880,980,640,300,'06','Developer outputs','M6 · M7')
icon('react',1912,1080,50,50);icon('fastapi',1980,1080,50,50);icon('electron',2048,1080,50,50);icon('github',2116,1080,50,50)
text(2190,1112,'Dashboard + Buddy',22,600)
text(1912,1165,'React / FastAPI · Electron desktop notifications',21)
text(1912,1204,'GitHub statuses + PR comment · HTML / JSON · SBOM',20)
rect(1909,1226,582,35,8,'#f4f5f6','none',0)
text(1925,1251,'Scan passed ≠ fix verified; show both outcomes.',20,650)
line('M630 1130H730');text(680,1106,'Approved',17,500,anchor='middle')
line('M1780 1130H1880');text(1830,1106,'Results',18,500,anchor='middle')
# Shared persistence and safeguards.
for x in [355,1255,2200]:line(f'M{x} 1280V1325',True,False)
rect(80,1325,2440,94,14,'#fafafa','#cbd0d5',2)
icon('sqlite',108,1345,140,49)
text(280,1361,'Evidence, audit & run state',25,650)
text(280,1396,'SQLite + SHA-256 blobs · run JSON · patches · hash-linked approval log · events / SSE · AI cache, token budget and ledger',22)
# Keep alternative modes visible but separate from the default runtime.
rect(80,1455,1460,132,12,'white','#dce0e5',1)
icon('agent-Brain',101,1474,43,43)
text(162,1504,'Deep investigation  ·  optional --deep  ·  LangGraph',24,650)
text(112,1543,'Lead → Dependency Hunter + Change Forensics → Skeptic → Lead re-plans',23,600)
text(112,1573,'Hunter: packages · Forensics: diffs, CI & sensitive files · Skeptic: independent review · Shared evidence board',18,400,'#68717b')
rect(1580,1455,940,132,12,'white','#dce0e5',1)
icon('agent-Scales',1601,1474,43,43)
text(1662,1504,'Scoring Advisor  ·  separate AI-assisted path',24,650)
text(1612,1543,'Context → matrix proposal → code checks → human approval',22,600)
text(1612,1573,'Approved AHP weights adjust priority only; hard floors and verdict stay fixed.',19,400,'#68717b')
# Milestones in one compact strip, all ten accounted for.
text(80,1634,'M0–M9  /  TEN MILESTONES',17,700,'#68717b')
ms=[('M0','Trust checks'),('M1','Scan engine'),('M2','Risk + states'),('M3','Investigation'),('M4','Fix + review'),('M5','Approve / test'),('M6','Reports'),('M7','Dashboard'),('M8','PR trigger'),('M9','Docs / diagram')]
for i,(m,label) in enumerate(ms):
 x=80+i*246;rect(x,1654,226,62,9,'white','#e0e3e7',1);text(x+14,1678,m,18,700);text(x+14,1703,label,19)
text(80,1755,'Scope: npm has the full remediation loop. Deep mode is the retained specialist loop; it is separate from the default workflow above.',19,400,'#68717b')
text(80,1784,'Validation scans the installed tree + build output; app-image build is outside the current profile. GitHub publishing requires token permissions. M0 applies throughout; M9 documents it.',18,400,'#68717b')
add('</g></svg>')
(D/'guardian-architecture.svg').write_text('\n'.join(p))
(D/'guardian-architecture.html').write_text('<!doctype html><meta charset="utf-8"><title>Guardian architecture</title><style>html,body{margin:0;background:#fff}img{display:block;width:100%;height:auto}</style><img src="guardian-architecture.svg" alt="Guardian architecture and agent roles">')
print(D/'guardian-architecture.svg')
