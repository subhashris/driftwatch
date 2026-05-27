"""
kev_check.py -- Cross-reference scan CVEs against CISA KEV
Reads kev.json (local) and checks each GHSA ID's CVE aliases against it.
"""
import subprocess
import json

ghsa_ids = [
    'GHSA-p9pc-299p-vxgp', 'GHSA-7p7h-4mm5-852v', 'GHSA-7fh5-64p2-3v2j',
    'GHSA-qx2v-qp2m-jg93', 'GHSA-wgrm-67xf-hhpq', 'GHSA-39q2-94rc-95cp',
    'GHSA-cj63-jhhr-wcxv', 'GHSA-cjmm-f4jc-qw8r', 'GHSA-crv5-9vww-q3g8',
    'GHSA-h7mw-gpvr-xq4m', 'GHSA-h8r8-wccr-v5f2', 'GHSA-vhxf-7vqr-mrjg',
    'GHSA-f886-m6hf-6m8v', 'GHSA-v6h2-p8h4-qcjw', 'GHSA-4w7w-66w2-5vf9',
    'GHSA-93m4-6634-74q7', 'GHSA-g4jq-h2w9-997c', 'GHSA-jqfw-vq24-v9c3',
    'GHSA-p9ff-h696-f583', 'GHSA-6rw7-vpxm-498p', 'GHSA-q8mj-m7cp-5q26',
    'GHSA-w7fw-mjwx-w883', 'GHSA-48c2-rrv3-qjmp'
]

# Load KEV
with open('kev.json', encoding='utf-8') as f:
    kev = {v['cveID']: v for v in json.load(f)['vulnerabilities']}

print(f'Loaded {len(kev)} KEV entries.')
print(f'Checking {len(ghsa_ids)} GHSA IDs...\n')

hits = []

for ghsa in ghsa_ids:
    print(f'  Checking {ghsa} ...', end=' ')
    query = f"SELECT aliases FROM osv.vulns WHERE id='{ghsa}'"
    r = subprocess.run(
        ['coral', 'sql', '--format', 'json', query],
        capture_output=True, text=True
    )
    if not r.stdout.strip():
        print('no data')
        continue
    try:
        data = json.loads(r.stdout.strip())
    except json.JSONDecodeError:
        print('parse error')
        continue
    if not data:
        print('empty')
        continue

    aliases_raw = data[0].get('aliases', '[]') or '[]'
    try:
        aliases = json.loads(aliases_raw)
    except json.JSONDecodeError:
        print('alias parse error')
        continue

    found = False
    for alias in aliases:
        if alias in kev:
            k = kev[alias]
            print(f'KEV HIT -> {alias}')
            hits.append({
                'ghsa': ghsa,
                'cve': alias,
                'product': k['product'],
                'name': k['vulnerabilityName'],
                'date_added': k['dateAdded'],
                'ransomware': k['knownRansomwareCampaignUse'],
                'due_date': k['dueDate'],
            })
            found = True
    if not found:
        cve_ids = [a for a in aliases if a.startswith('CVE-')]
        print(f'not in KEV (aliases: {", ".join(cve_ids) or "none"})')

print('\n' + '=' * 60)
if hits:
    print(f'FOUND {len(hits)} KEV HIT(S) IN YOUR DEPENDENCY TREE:\n')
    for h in hits:
        print(f'  {h["ghsa"]} -> {h["cve"]}')
        print(f'  Product    : {h["product"]}')
        print(f'  Vuln       : {h["name"]}')
        print(f'  Added      : {h["date_added"]}')
        print(f'  Ransomware : {h["ransomware"]}')
        print(f'  Due Date   : {h["due_date"]}')
        print()
else:
    print('No KEV hits found in this set.')
    print('(This is the correct/honest result if none apply.)')
    print('For demo purposes, consider scanning a larger repo')
    print('or using a repo with older, known-exploited dependencies.')
