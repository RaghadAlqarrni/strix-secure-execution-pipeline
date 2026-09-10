#!/usr/bin/env python3
"""Reject raw/summary contradictions while the synthesized summary stays green."""
import copy, hashlib, json, os, sys, tempfile
from pathlib import Path
HERE=os.path.dirname(os.path.abspath(__file__)); PEP=os.path.dirname(HERE); sys.path[:0]=[PEP,HERE]
import make_fixtures as F
from verify_b7_evidence import derive
def put(d,n,data,binary=False):
 p=os.path.join(d,n)
 with open(p,'wb' if binary else 'w',encoding=None if binary else 'utf-8') as f:f.write(data)
 return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def build(d,e,kind):
 src=e['sender']['src_ip']; dst=e['target']['ip']; port=e['target']['port']; rid=e['run_id']; ni='a'*64; ne='b'*64; cid='c'*64; pid=4242; veth='vethB7'; br='br-'+ni[:12]
 e['sender'].update(container_id=cid,container_pid=pid,host_veth=veth,network_id=ni); e['target']['network_id']=ne
 e['packet_attempt']['pcap_sha256']=put(d,'attempt.pcap',b'pcap'+e['probe']['nonce'].encode(),True)
 receiver='\n'.join(json.dumps({'nonce':n}) for n in (e['controls']['c1_nonce'],e['controls']['c2_nonce']))+'\n'
 if kind=='receiver-contradiction': receiver+=json.dumps({'nonce':e['probe']['nonce']})+'\n'
 e['receiver']['raw_log_sha256']=put(d,'receiver.jsonl',receiver)
 e['calibration']['raw_log_sha256']=put(d,'cal_receiver.jsonl',json.dumps({'nonce':e['calibration']['nonce']})+'\n')
 rule=f'-A PREROUTING -i {br} -s {src}/128 -d {dst}/128 -p udp -m udp --dport {port} -m comment --comment "strix-b7:{rid}" -j DROP'
 if kind=='broad-rule': rule=f'-A PREROUTING -d {dst}/128 -j DROP'
 e['enforcement'].update(rule_identity=rule,packets_before=10,packets_after=11); after=10 if kind=='counter-contradiction' else 11
 put(d,'rules.before',f'[10:1000] {rule}\n'); put(d,'rules.after',f'[{after}:1112] {rule}\n')
 sbxid='d'*64 if kind=='identity-contradiction' else cid
 put(d,'sandbox.inspect.json',json.dumps([{'Id':sbxid,'State':{'Pid':pid},'NetworkSettings':{'Networks':{'gate_prog_a':{'GlobalIPv6Address':src}}}}])); put(d,'receiver.inspect.json',json.dumps([{'NetworkSettings':{'Networks':{'gate_egress':{'GlobalIPv6Address':dst}}}}])); put(d,'network-in.inspect.json',json.dumps([{'Id':ni,'Name':'gate_prog_a','Options':{}}])); put(d,'network-eg.inspect.json',json.dumps([{'Id':ne,'Name':'gate_egress'}])); put(d,'host-links.json',json.dumps([{'ifname':veth}])); put(d,'sandbox-ipv6-addr.json','[]'); put(d,'sandbox-ipv6-route-before.json','[]')
def main():
 cases=[('honest',True),('receiver-contradiction',False),('counter-contradiction',False),('identity-contradiction',False),('broad-rule',False)]; good=0
 for kind,want in cases:
  a=F.honest_artifacts(); e=copy.deepcopy(a['b7']); lb=copy.deepcopy(a['layerb'])
  with tempfile.TemporaryDirectory() as d: build(d,e,kind); got,fail=derive(e,lb,F.RID,d)
  ok=got is want; good+=ok; print(f"  {'PASS' if ok else 'FAIL'} raw {kind:24} expected={want} got={got} failures={fail[:2]}")
 print(f"E9 RAW CONTRADICTIONS: {good}/{len(cases)}"); return 0 if good==len(cases) else 1
if __name__=='__main__': raise SystemExit(main())
