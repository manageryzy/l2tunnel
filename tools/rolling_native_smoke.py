#!/usr/bin/env python3
"""Finite W32 rolling native acceptance; dry-run unless --apply is explicit."""
from __future__ import annotations
import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import signal
import stat
import struct
import subprocess
import sys
import tempfile
import time
try:
    from . import proxy_native_smoke as bounded
    from . import raw_packet_native_smoke as transparent
except ImportError:
    import proxy_native_smoke as bounded
    import raw_packet_native_smoke as transparent
netns_lab = bounded.netns_lab
ROOT = Path(__file__).resolve().parents[1]
BOUNDS = {'case': 150, 'startup': 35, 'command': 10, 'transfer': 30,
          'outage': 2, 'settle': 1, 'cleanup': 30, 'shared_helper_command': 15}
MAX_SAMPLES = 64
APPLICATION_ID = b'rolling-nativ-01'
HELPERS = {'tools/rolling_native_smoke.py': Path(__file__),
           'tools/proxy_native_smoke.py': Path(bounded.__file__),
           'tools/raw_packet_native_smoke.py': Path(transparent.__file__),
           'tools/raw_native_smoke.py': Path(transparent.retained.__file__),
           'tools/netns_lab.py': Path(netns_lab.__file__)}


def policy() -> dict:
    return {'version': 1, 'profile': 'rolling-frame-v1', 'channels': 4, 'stream': 1, 'epoch': 1,
            'recovery': {'window': 32, 'local_window': 8, 'global_every': 16, 'max_payload': 1000,
                'max_rows': 32, 'repair_history': 64, 'handoff_sources': 8, 'job_millis': 5000,
                'debt_millis': 20000, 'handoff_millis': 5000, 'memory_bytes': 33554432},
            'scheduling': {'repair_numerator': 1, 'repair_denominator': 2, 'tail_millis': 20,
                'feedback_millis': 5, 'feedback_packets': 4, 'memory_bytes': 33554432},
            'service': {'field_work': 4096, 'copy_work': 4096, 'metadata_work': 4096, 'passes_per_turn': 8}}


def case_plan(lab_id: str, carrier: str, layer: str, duplex: str, profile: str) -> dict:
    if carrier not in ('udp', 'quic') or layer not in ('tap', 'tun') or duplex not in ('full', 'half') or profile not in ('clean', 'loss'):
        raise ValueError('explicit supported rolling carrier/layer/duplex/profile required')
    spec = netns_lab.LabSpec(f'{lab_id}-{carrier[0]}{layer[1]}{duplex[0]}{profile[0]}')
    network = 18 if layer == 'tap' else 19
    return {'case': f'{carrier}-{layer}-{duplex}-{profile}', 'lab_id': spec.lab_id,
            'carrier': carrier, 'layer': layer, 'duplex': duplex, 'profile': profile,
            'lanes': 1 if duplex == 'full' else 2, 'namespaces': spec.namespaces,
            'policy': policy(), 'path_mtu': 1500, 'max_packet': 1600,
            'udp_cover': 'quic-like' if carrier == 'udp' else 'not_applicable',
            'protection': 'integrity' if carrier == 'udp' else 'maintained_quic_aead',
            'netem': {'delay_ms': 35 if profile == 'loss' else 1, 'loss_percent': 15 if profile == 'loss' else 0},
            'flows': [{'family': f, 'source': f'198.{network}.0.1' if f == 4 else f'fd42:12:{network}::1',
                       'destination': f'198.{network}.0.2' if f == 4 else f'fd42:12:{network}::2',
                       'source_port': 32000 + f, 'destination_port': 24451} for f in (4, 6)],
            'bounds_seconds': dict(BOUNDS), 'initial_topology_commands': netns_lab.plan_document(spec)['commands'],
            'graceful_close': False,
            'not_qualified': ['W8192', 'complete Python family', 'fairness/throughput', 'alternate UDP covers/suites', 'clean drain', 'other platforms']}


def daemon_command(plan: dict, side: str, binary: Path, secrets: Path, policy_path: Path, control: Path) -> list[str]:
    if side not in ('a', 'b'):
        raise ValueError('explicit peer required')
    local, peer = ('192.0.2.2', '192.0.2.6') if side == 'a' else ('192.0.2.6', '192.0.2.2')
    address = '192.0.2.6:' + ('24440' if plan['carrier'] == 'quic' else '18443')
    flags = (['connect', '--remote', address, '--ca', str(secrets/'cert.der'), '--server-name', 'lab.invalid', '--identity', str(secrets/'member.der')]
             if side == 'a' else ['serve', '--listen', address, '--cert', str(secrets/'cert.der'), '--key', str(secrets/'server.der'), '--allow-key', str(secrets/'member.pub')])
    flags += ['--record-profile', 'rolling', '--rolling-policy', str(policy_path), '--carrier', plan['carrier'],
              '--layer', plan['layer'], '--device', plan['layer']+'0', '--duplex', plan['duplex'], '--traffic', 'system',
              '--compression', 'off', '--max-packet', '1600', '--path-mtu', '1500', '--control-socket', str(control),
              '--udp-bind', local+':24440', '--udp-peer', peer+':24440']
    if plan['duplex'] == 'half':
        flags += ['--udp-reverse-bind', local+':24441', '--udp-reverse-peer', peer+':24441']
    flags += (['--udp-cover', 'quic-like', '--udp-protection', 'integrity'] if plan['carrier'] == 'udp'
              else ['--quic-application-id', APPLICATION_ID.hex()])
    return ['ip', 'netns', 'exec', plan['namespaces']['endpoint_'+side], str(binary), *flags]


def validate_snapshot(value: dict, plan: dict, digest: str | None = None, phase: str = 'forwarding') -> dict:
    fields = {'profile','requested_carrier','effective_carrier','requested_cover','effective_cover','layer','duplex','pipeline','channels','window','max_payload','epoch','digest','phase','hot_reload','clean_drain','tcp_window_ownership','native_qualified','large_window_qualified','failure'}
    cover = 'quic_like' if plan['carrier'] == 'udp' else 'not_applicable'
    expected = {'profile':'rolling-frame-v1','requested_carrier':plan['carrier'],'effective_carrier':plan['carrier'],
                'requested_cover':cover,'effective_cover':cover,'layer':plan['layer'],'duplex':plan['duplex'],
                'pipeline':'tap_system' if plan['layer']=='tap' else 'tun_drr','channels':4,'window':32,'max_payload':1000,'epoch':1,
                'phase':phase,'failure':None,'hot_reload':False,'clean_drain':False,'tcp_window_ownership':False,
                'native_qualified':False,'large_window_qualified':False}
    if not isinstance(value,dict) or set(value)!=fields or any(value[k]!=v or type(value[k]) is not type(v) for k,v in expected.items()):
        raise ValueError('actual rolling selected policy/lifecycle mismatch')
    if not isinstance(value['digest'],str) or not re.fullmatch('[0-9a-f]{64}',value['digest']) or digest is not None and value['digest']!=digest:
        raise ValueError('actual rolling digest mismatch')
    return value


def validate_status(response: dict, plan: dict, digest: str | None = None, allow_authenticated: bool=False) -> dict:
    if not isinstance(response,dict) or set(response)!={'version','ok','code','state'} or type(response['version']) is not int or response['version']!=1 or response['ok'] is not True or response['code']!='ok':
        raise ValueError('strict rolling local response required')
    s=response['state']
    if not isinstance(s,dict) or set(s)!={'epoch','phase','compression','rolling'} or type(s['epoch']) is not int or s['epoch']!=1 or s['phase'] not in (('authenticated','forwarding') if allow_authenticated else ('forwarding',)) or s['compression']!='off':
        raise ValueError('rolling local envelope mismatch')
    return validate_snapshot(s['rolling'],plan,digest,s['phase'])


def namespace_observation(spec) -> dict:
    result={}
    for name in spec.namespaces.values():
        try: value=(netns_lab.NETNS_DIRECTORY/name).lstat()
        except FileNotFoundError: result[name]=None
        else: result[name]=(value.st_dev,value.st_ino,stat.S_IFMT(value.st_mode))
    return result


def verify_helpers(build: dict, output: Path, loaded: bool=False) -> dict:
    result={}
    for name,source in HELPERS.items():
        path=output/Path(name).name;digest=build.get('source_sha256_after',{}).get(name)
        if path.is_symlink() or not path.is_file() or not isinstance(digest,str) or bounded.file_hash(path)!=digest or loaded and source.resolve()!=path.resolve():
            raise ValueError('copied/executed helper differs from original exact build: '+name)
        result[name]=digest
    return result


def underlay_records(path: Path, plan: dict) -> list[dict]:
    if path.stat().st_size>=bounded.CAPTURE_LIMIT: raise bounded.CaptureBound('underlay byte cap')
    data=path.read_bytes();magics={b'\xd4\xc3\xb2\xa1':('<',1000),b'\xa1\xb2\xc3\xd4':('>',1000),b'\x4d\x3c\xb2\xa1':('<',1),b'\xa1\xb2\x3c\x4d':('>',1)}
    if len(data)<24 or data[:4] not in magics: raise ValueError('pcap header')
    endian,unit=magics[data[:4]];major,minor,zone,accuracy,snaplen,link=struct.unpack_from(endian+'HHiiii',data,4)
    if (major,minor,zone,accuracy,link)!=(2,4,0,0,1) or not 1500<=snaplen<=262144: raise ValueError('pcap geometry')
    rows=[];cursor=24;ips={ipaddress.ip_address('192.0.2.2').packed:0,ipaddress.ip_address('192.0.2.6').packed:1}
    while cursor<len(data):
        if len(data)-cursor<16: raise ValueError('pcap record header')
        seconds,fraction,captured,original=struct.unpack_from(endian+'IIII',data,cursor);cursor+=16
        if fraction>=1000000000//unit or captured!=original or not 34<=captured<=snaplen or captured>len(data)-cursor: raise ValueError('pcap truncation/precision')
        frame=data[cursor:cursor+captured];cursor+=captured
        if frame[12:14]!=b'\x08\x00': raise ValueError('underlay Ethernet type')
        ip=frame[14:];header=(ip[0]&15)*4;total=int.from_bytes(ip[2:4],'big')
        if ip[0]>>4!=4 or header<20 or total!=len(ip) or total>plan['path_mtu'] or total<header+8 or int.from_bytes(ip[6:8],'big')&0xbfff or bounded.checksum(ip[:header]): raise ValueError('underlay IP extent/checksum/fragment/MTU')
        source,target=ip[12:16],ip[16:20]
        if source not in ips or target not in ips or source==target: raise ValueError('underlay tuple')
        body=ip[header:];sport,dport=struct.unpack_from('!HH',body);direction=ips[source]
        if ip[9]==17:
            length=int.from_bytes(body[4:6],'big');ports={24440,24441} if plan['duplex']=='half' else {24440}
            if sport!=dport or sport not in ports or length!=len(body) or length<=8: raise ValueError('UDP lane/extent')
            if int.from_bytes(body[6:8],'big') and bounded.checksum(source+target+bytes([0,17])+len(body).to_bytes(2,'big')+body): raise ValueError('UDP checksum')
            row={'protocol':'udp','lane':sport-24440,'direction':direction,'body':body[8:]}
        elif ip[9]==6 and plan['carrier']=='udp':
            size=(body[12]>>4)*4 if len(body)>=20 else 0
            if 18443 not in (sport,dport) or not 20<=size<=len(body) or bounded.checksum(source+target+bytes([0,6])+len(body).to_bytes(2,'big')+body): raise ValueError('TLS control tuple/header/checksum')
            row={'protocol':'tcp','direction':direction,'payload_bytes':len(body)-size,'server_port':18443,'client_port':sport if direction==0 else dport,'sequence':int.from_bytes(body[4:8],'big'),'acknowledgment':int.from_bytes(body[8:12],'big'),'flags':body[13]}
        else: raise ValueError('unexpected underlay protocol')
        row.update(at_ns=seconds*1000000000+fraction*unit,ip_bytes=total);rows.append(row)
        if len(rows)>=bounded.PACKET_LIMIT: raise bounded.CaptureBound('underlay packet cap')
    if not rows: raise ValueError('empty underlay capture')
    return rows


def rolling_record(body: bytes, lane: int, direction: int) -> dict:
    # Fixed QUIC-like prefix + LD header + full HMAC tag; structural only.
    if len(body)<85: raise ValueError('visible protected UDP extent')
    h=body[9:53];vector=body[53:-32]
    if body[0]!=0x40 or body[1:9]!=h[8:16] or h[:6]!=b'LD\x01\x02\x02'+bytes([direction+1]) or h[6:8]!=bytes(2) or h[42:44]!=bytes(2) or int.from_bytes(h[24:28],'big')!=lane or h[28:32]!=bytes(4) or int.from_bytes(h[40:42],'big')!=len(vector): raise ValueError('outer visible structural domain')
    if len(vector)!=1066 or vector[:5]!=b'L2RW\x01' or vector[5] not in (1,2) or vector[6]&~1 or vector[7] or vector[37:40]!=bytes(3) or vector[62:64]!=bytes(2) or vector[8:24]!=h[8:24] or int.from_bytes(vector[24:32],'big')!=1 or int.from_bytes(vector[32:36],'big')!=1+lane or vector[36]!=direction or int.from_bytes(vector[60:62],'big')!=1002: raise ValueError('rolling structural scope/extent')
    identity,start,end,seed=struct.unpack_from('!QIII',vector,40)
    if vector[5]==1:
        length=int.from_bytes(vector[64:66],'big')
        if identity>=0xffffffff or (start,end,seed,vector[6])!=(identity,identity+1,0,0) or not 42<length<=1000 or vector[66+length:]!=bytes(1000-length) or int.from_bytes(vector[66:68],'big')>=4: raise ValueError('source support/exact padding/channel')
        kind='source'
    else:
        tail=bool(vector[6]);global_support=tail or (identity&0x7fff)%16==0;expected_start=max(0,end-(32 if global_support else 8))
        # The seeded support is independently checked from its published formula.
        serial=(identity&0xffffffff) if tail else (identity&0x7fff)
        expected_seed=(serial*2654435761)&0xffffffff
        if not 0<identity<0xffffffffffffffff or end==0 or start!=expected_start or seed!=expected_seed: raise ValueError('repair identity/support/seed')
        kind='repair'
    return {'kind':kind,'id':identity,'lane':lane,'direction':direction,'scope':vector[8:40].hex(),'body_sha256':hashlib.sha256(vector).hexdigest()}


def clock_anchor()->dict:
    before=time.monotonic_ns();real=time.time_ns();after=time.monotonic_ns()
    return {'before_mono_ns':before,'realtime_ns':real,'after_mono_ns':after}


def outage_clock_interval(start:dict,end:dict)->dict:
    for value in (start,end):
        if set(value)!={'before_mono_ns','realtime_ns','after_mono_ns'} or any(type(n) is not int or n<0 for n in value.values()) or not 0<=value['after_mono_ns']-value['before_mono_ns']<=1000000:
            raise ValueError('bounded original outage clock bracket required')
    first=start['realtime_ns']-(start['before_mono_ns']+start['after_mono_ns'])//2
    last=end['realtime_ns']-(end['before_mono_ns']+end['after_mono_ns'])//2
    if abs(last-first)>5000000 or end['before_mono_ns']<=start['after_mono_ns'] or end['realtime_ns']<=start['realtime_ns']:
        raise ValueError('outage realtime/monotonic clock drift or regression')
    return {'start_ns':start['realtime_ns']+6000000,'end_ns':end['realtime_ns']-6000000,'uncertainty_ns':6000000,'start_clock':start,'end_clock':end}


def tls_outage_progress(controls:list[dict],outage:dict,connections:set[int])->set[int]:
    """Fresh post-auth control bytes plus actual peer ACKs inside the original outage."""
    progress=set()
    for port in connections:
        stream=[r for r in controls if r['client_port']==port]
        for direction in (0,1):
            sent=[r for r in stream if r['direction']==direction]
            syn={r['sequence'] for r in sent if r['flags']&2}
            if len(syn)!=1: raise ValueError('retained TLS must have one original SYN per direction')
            base=(next(iter(syn))+1)&0xffffffff
            def offset(sequence):
                result=(sequence-base)&0xffffffff
                if result>=2**31: raise ValueError('control sequence horizon')
                return result
            data=[r for r in sent if r['payload_bytes']]
            before=max([offset(r['sequence'])+r['payload_bytes'] for r in data if r['at_ns']<=outage['start_ns']]+[0])
            fresh=[r for r in data if outage['start_ns']<r['at_ns']<outage['end_ns'] and offset(r['sequence'])>=before]
            acks=[r for r in stream if r['direction']!=direction and r['flags']&16 and outage['start_ns']<r['at_ns']<outage['end_ns']]
            if not any(any(r['at_ns']<=ack['at_ns'] and offset(ack['acknowledgment'])>=offset(r['sequence'])+r['payload_bytes'] for ack in acks) for r in fresh):
                raise ValueError('fresh retained TLS bytes plus new peer ACK missing during UDP outage')
        progress.add(port)
    return progress


def audit_underlay(paths: dict[str,Path], plan: dict, outage: dict | None) -> dict:
    captures={side:underlay_records(path,plan) for side,path in paths.items()}
    if set(captures)!={'a','b'}: raise ValueError('both underlay captures required')
    expected={(0,0),(0,1)} if plan['duplex']=='full' else ({(0,0),(1,1)} if plan['carrier']=='udp' else {(i,d) for i in (0,1) for d in (0,1)})
    audit={};peer_views={}
    for side,rows in captures.items():
        data=[r for r in rows if r['protocol']=='udp'];seen={(r['lane'],r['direction']) for r in data}
        if seen!=expected: raise ValueError('actual data lane/direction coverage mismatch')
        report={'packets':len(rows),'udp_packets':len(data),'maximum_ip_bytes':max(r['ip_bytes'] for r in rows),'observed_lanes':sorted(map(list,seen))}
        if plan['carrier']=='udp':
            observed={};kinds={};scopes={};nonces={};nonce_kinds={}
            for row in data:
                value=rolling_record(row['body'],row['lane'],row['direction'])
                key=(value['lane'],value['direction'],value['kind'],value['id'])
                if key in observed and observed[key]!=value['body_sha256']: raise ValueError('conflicting duplicate rolling wire identity')
                observed[key]=value['body_sha256'];kinds.setdefault((value['lane'],value['direction']),set()).add(value['kind'])
                domain=(value['lane'],value['direction']);scope=value['scope']
                if domain in scopes and scopes[domain]!=scope: raise ValueError('rolling domain changed during capture')
                scopes[domain]=scope
                h=row['body'][9:53];nonce=(domain,int.from_bytes(h[32:40],'big'))
                digest=hashlib.sha256(row['body']).hexdigest()
                if nonce in nonces and nonces[nonce]!=digest: raise ValueError('conflicting outer nonce')
                nonces[nonce]=digest
                nonce_kinds[nonce]=value['kind']
            if any(kinds.get(key)!={'source','repair'} for key in expected): raise ValueError('missing actual source/repair in each bulk direction')
            controls=[r for r in rows if r['protocol']=='tcp'];connections={r['client_port'] for r in controls}
            if len(connections)!=plan['lanes'] or any(not {r['direction'] for r in controls if r['client_port']==port and r['payload_bytes']}.issuperset({0,1}) for port in connections): raise ValueError('retained TLS lane traffic missing')
            if not outage or type(outage.get('start_ns')) is not int or type(outage.get('end_ns')) is not int or outage['end_ns']<=outage['start_ns']: raise ValueError('original UDP outage interval missing')
            progress=tls_outage_progress(controls,outage,connections)
            peer_views[side]={'scopes':scopes,'nonces':nonces,'records':observed,'nonce_kinds':nonce_kinds}
            report.update(rolling_sources=sum(key[2]=='source' for key in observed),rolling_repairs=sum(key[2]=='repair' for key in observed),tls_lanes=len(connections),tls_lanes_progressing_during_udp_outage=len(progress),scope='structural visible records only; no HMAC authentication or repair-causality claim')
        else:
            if outage is not None or any(r['protocol']!='udp' for r in rows): raise ValueError('genuine QUIC must have UDP-only outer capture')
            peer_views[side]={(r['lane'],r['direction'],hashlib.sha256(r['body']).hexdigest()) for r in data}
            report['scope']='encrypted QUIC outer tuple/size only; no rolling plaintext claim'
        audit[side]=report
    if plan['carrier']=='udp':
        a,b=peer_views['a'],peer_views['b']
        if a['scopes']!=b['scopes']: raise ValueError('peer captures disagree on rolling session/scope')
        common_nonces=a['nonces'].keys()&b['nonces'].keys()
        if any(a['nonces'][key]!=b['nonces'][key] for key in common_nonces):
            raise ValueError('same protected counter differs across peer captures')
        if any(not any(key[0]==domain and a['nonce_kinds'][key]==kind for key in common_nonces)
               for domain in expected for kind in ('source','repair')):
            raise ValueError('no common source and repair protected packets in each bulk direction')
        common_records=a['records'].keys()&b['records'].keys()
        if any(a['records'][key]!=b['records'][key] for key in common_records):
            raise ValueError('same rolling record differs across peer captures')
        if any(not any(key[:3]==(lane,direction,kind) for key in common_records)
               for lane,direction in expected for kind in ('source','repair')):
            raise ValueError('no common source and repair in each bulk direction')
        for report in audit.values():
            report['common_protected_counters']=len(common_nonces)
            report['common_rolling_records']=len(common_records)
    else:
        common=peer_views['a']&peer_views['b']
        if any(not any(key[:2]==domain for key in common) for domain in expected):
            raise ValueError('no common opaque QUIC datagram in each lane/direction')
        for report in audit.values(): report['common_opaque_datagrams']=len(common)
    return audit


def validate_ping(text:str,code:int,positive:bool)->None:
    expected=(1,1,0.0) if positive else (1,0,100.0)
    match=re.search(r'(\d+) packets transmitted, (\d+) received,.*?([0-9.]+)% packet loss',text)
    if code!=(0 if positive else 1) or match is None or (int(match[1]),int(match[2]),float(match[3]))!=expected:
        raise ValueError('native positive/negative probe failed: '+text[:4096])


def validate_netem(text:str,plan:dict)->None:
    delay=re.search(r'\bdelay ([0-9.]+)ms\b',text)
    loss=re.search(r'\bloss (?:random )?([0-9.]+)%',text)
    if delay is None or float(delay[1])!=plan['netem']['delay_ms'] or (float(loss[1]) if loss else 0)!=plan['netem']['loss_percent']:
        raise ValueError('fixed owned netem profile not observed')


def run_case(plan:dict,binary:Path,harness:Path,output:Path,secrets:Path,state_dir:Path)->dict:
    start=time.monotonic();end=start+BOUNDS['case'];spec=netns_lab.LabSpec(plan['lab_id']);ns=spec.namespaces
    case=output/plan['case'];case.mkdir();control=case/'control';control.mkdir(mode=0o700);parent=control.stat()
    sockets={s:control/(s+'.sock') for s in ('a','b')};socket_owners={p:(parent.st_dev,parent.st_ino) for p in sockets.values()}
    receipt=bounded.Receipt(case/'receipt.json',{'status':'running','stage':'preflight','plan':plan,'cleanup':'pending','graceful_close':False})
    before=namespace_observation(spec);created=False;failure=None;processes=[];captures={};paths={};daemons={};samples=[];outage=None
    def owned(): return transparent.retained.owned(spec,state_dir)
    def run(argv,cap=10):
        owned();return bounded.command(argv,end,cap)
    def nsrun(side,*args,native=False):
        role='host_'+side if native and plan['layer']=='tap' else 'endpoint_'+side
        return ['ip','netns','exec',ns[role],*args]
    def stage(name,**fields): receipt.update(stage=name,**fields)
    def inspect():
        owned()
        if any(p.poll() is not None for p,_ in daemons.values()): raise RuntimeError('original daemon exited before explicit cancellation')
    def statuses(deadline,starting=False):
        inspect()
        if len(samples)>=MAX_SAMPLES: raise bounded.CaptureBound('status sample cap')
        values={s:validate_status(bounded.rpc(p,'status',deadline),plan,allow_authenticated=starting) for s,p in sockets.items()}
        if values['a']['digest']!=values['b']['digest']: raise ValueError('authenticated peer digest disagreement')
        samples.append({'at_monotonic':time.monotonic(),'peers':values});return values
    try:
        if any(v is not None for v in before.values()): raise ValueError('refusing existing expected namespace')
        bounded.bounded_lab(netns_lab.apply,spec,state_dir,end);created=True;owned()
        features={};network=18 if plan['layer']=='tap' else 19
        for side,number in (('a','1'),('b','2')):
            run(nsrun(side,'tc','qdisc','change','dev','wan0','parent','1:10','handle','10:','netem','limit','1000','delay',str(plan['netem']['delay_ms'])+'ms','loss','random',str(plan['netem']['loss_percent'])+'%'))
            text=run(nsrun(side,'tc','-s','qdisc','show','dev','wan0'))
            validate_netem(text,plan)
            if plan['layer']=='tun':
                run(['ip','-n',ns['endpoint_'+side],'tuntap','add','dev','tun0','mode','tun'])
                run(['ip','-n',ns['endpoint_'+side],'link','set','tun0','mtu','1500','up'])
                run(['ip','-n',ns['endpoint_'+side],'address','add','198.19.0.'+number+'/24','dev','tun0'])
            native=ns['host_'+side if plan['layer']=='tap' else 'endpoint_'+side];interface='eth0' if plan['layer']=='tap' else 'tun0'
            run(['ip','-n',native,'-6','address','add',f'fd42:12:{network}::{number}/64','dev',interface,'nodad'])
            for label,namespace,device in [('wan',ns['endpoint_'+side],'wan0'),('native',native,interface)]: features[side+'_'+label]=bounded.offloads(namespace,device,min(end,time.monotonic()+BOUNDS['command']))
            run(nsrun(side,'tc','qdisc','add','dev','wan0','clsact'))
        for interface in ('a0','b0'): features['router_'+interface]=bounded.offloads(ns['router'],interface,min(end,time.monotonic()+BOUNDS['command']))
        underlay_ipv6=bounded.disable_underlay_ipv6(ns,min(end,time.monotonic()+BOUNDS['command']))
        if plan['layer']=='tap':
            mac={s:json.loads(run(['ip','-j','-n',ns['host_'+s],'link','show','dev','eth0']))[0]['address'] for s in ('a','b')}
            for s,peer in (('a','b'),('b','a')):
                number='2' if peer=='b' else '1'
                for address in (f'198.18.0.{number}',f'fd42:12:18::{number}'):
                    run(['ip','-n',ns['host_'+s],'neigh','replace',address,'lladdr',mac[peer],'nud','permanent','dev','eth0'])
        blocked={}
        if plan['carrier']=='quic':
            for s,peer in (('a','192.0.2.6'),('b','192.0.2.2')):
                run(nsrun(s,'tc','filter','add','dev','wan0','egress','protocol','ip','pref','1','u32','match','ip','protocol','6','0xff','action','drop'))
                result=run(nsrun(s,sys.executable,str(harness),'tcp-block-probe',peer),2)
                text=run(nsrun(s,'tc','-s','filter','show','dev','wan0','egress','pref','1'),2)
                if result.strip()!='TCP blocked by timeout' or not any(int(n)>0 for n in re.findall(r'dropped\s+(\d+)',text)): raise ValueError('genuine QUIC TCP block has no actual SYN/drop evidence')
                blocked[s]={'probe':result,'filter':text}
        stage('prearm_capture',identities=owned(),offloads=features,underlay_ipv6=underlay_ipv6,tcp_blocked=blocked)
        for s in ('a','b'):
            for label,interface,native in [('wan','wan0',False),('native','eth0' if plan['layer']=='tap' else 'tun0',True)]:
                key=s+'_'+label;path=case/(key+'.pcap');log=case/(key+'-capture.log')
                filt=['udp','and','(','port','24440','or','port','24441',')'] if label=='wan' else ['(','ip','and','net',f'198.{network}.0.0/24',')','or','(','ip6','and','net',f'fd42:12:{network}::/64',')']
                if label=='wan' and plan['carrier']=='udp': filt=['(',*filt,')','or','(','tcp','port','18443',')']
                owned();p=bounded.start_capture(nsrun(s,'tcpdump','-U','-n','-i',interface,'-s','0','-c',str(bounded.PACKET_LIMIT),'-w',str(path),*filt,native=native),log,min(end,time.monotonic()+5))
                captures[key]=(p,log);paths[key]=path;processes.append(p)
        policy_path=case/'rolling-policy.json';policy_path.write_text(json.dumps(plan['policy'],sort_keys=True)+'\n')
        stage('authenticate_original_lanes')
        for s in ('b','a'):
            log=case/(s+'-daemon.log');owned();p=bounded.launch(daemon_command(plan,s,binary,secrets,policy_path,sockets[s]),log);daemons[s]=(p,log);processes.append(p)
            if s=='b':
                ready=min(end,time.monotonic()+BOUNDS['startup'])
                while True:
                    if p.poll() is not None: raise RuntimeError('server exited before original endpoint bind: '+bounded.read_log(log))
                    text=run(nsrun(s,'ss','-Hlunt'),2)
                    if re.search(r':'+('24440' if plan['carrier']=='quic' else '18443')+r'\b',text): break
                    time.sleep(min(.05,bounded.remaining(ready,.05)))
        ready=min(end,time.monotonic()+BOUNDS['startup'])
        while True:
            try:
                peers=statuses(ready,True)
                if all(value['phase']=='forwarding' for value in peers.values()): break
                time.sleep(min(.05,bounded.remaining(ready,.05)))
            except (FileNotFoundError,ConnectionRefusedError,TimeoutError): time.sleep(min(.05,bounded.remaining(ready,.05)))
        digest=peers['a']['digest']
        for p,log in daemons.values():
            proof=transparent.event(bounded.read_log(log),'rolling_authenticated')
            if set(proof)!={'event','state'}: raise ValueError('rolling authentication event fields')
            validate_snapshot(proof['state'],plan,digest,'authenticated')
        stage('native_ipv4_ipv6',authenticated=peers)
        pings=[]
        def ping(s,address,family,positive=True):
            argv=nsrun(s,'ping','-'+str(family),'-n','-c','1','-W','3' if positive else '1','-s','117',address,native=True)
            owned();completed=subprocess.run(argv,capture_output=True,text=True,timeout=bounded.remaining(end,5))
            validate_ping(completed.stdout+completed.stderr,completed.returncode,positive)
            return {'side':s,'family':family,'positive':positive,'stdout':completed.stdout}
        for s,n in (('a','2'),('b','1')):
            for f,address in ((4,f'198.{network}.0.{n}'),(6,f'fd42:12:{network}::{n}')): pings.append(ping(s,address,f))
        batch=[];transfers=[];transfer_end=min(end,time.monotonic()+BOUNDS['transfer'])
        for flow in plan['flows']:
            for s,role in (('b','listen'),('a','connect')):
                log=case/(str(flow['family'])+'-'+role+'.log');owned();p=bounded.launch(nsrun(s,sys.executable,str(harness),'probe',role,flow['source'],flow['destination'],str(flow['source_port']),str(flow['destination_port']),native=True),log)
                processes.append(p);batch.append((p,log,flow,role))
                if role=='listen': bounded.wait_log(p,log,'Listening',transfer_end)
        for p,log,flow,role in batch:
            if p.wait(timeout=bounded.remaining(transfer_end,BOUNDS['transfer']))!=0: raise RuntimeError('exact native TCP failed: '+bounded.read_log(log))
            value=bounded.strict_json(bounded.read_log(log).splitlines()[-1]);bounded.verify_probe(value,flow,role);transfers.append(value)
        statuses(end)
        if plan['carrier']=='udp':
            stage('interrupt_only_udp',transfers=transfers)
            for s in ('a','b'): run(nsrun(s,'tc','filter','add','dev','wan0','egress','protocol','ip','pref','20','u32','match','ip','protocol','17','0xff','action','drop'),2)
            start_clock=clock_anchor();outage={'start_monotonic':start_clock['after_mono_ns']/1000000000}
            negative=[];negative_end=min(end,outage['start_monotonic']+BOUNDS['outage'])
            for side,number in (('a','2'),('b','1')):
                log=case/(side+'-udp-blocked-probe.log');owned()
                process=bounded.launch(nsrun(side,'ping','-4','-n','-c','1','-W','1','-s','117',f'198.{network}.0.{number}',native=True),log)
                processes.append(process);negative.append((side,process,log))
            for side,process,log in negative:
                code=process.wait(timeout=bounded.remaining(negative_end,BOUNDS['outage']));text=bounded.read_log(log);validate_ping(text,code,False)
                pings.append({'side':side,'family':4,'positive':False,'stdout':text})
            statuses(end)
            until=outage['start_monotonic']+BOUNDS['outage']
            while True:
                delay=until-time.monotonic()
                if delay<=0: break
                bounded.remaining(end,.05);time.sleep(min(.05,delay))
            outage['filters']={s:run(nsrun(s,'tc','-s','filter','show','dev','wan0','egress','pref','20'),2) for s in ('a','b')}
            if any(not any(int(n)>0 for n in re.findall(r'dropped\s+(\d+)',text)) for text in outage['filters'].values()): raise ValueError('UDP interruption lacks actual dropped data evidence on both peers')
            end_clock=clock_anchor();outage.update(outage_clock_interval(start_clock,end_clock));outage['end_monotonic']=end_clock['before_mono_ns']/1000000000
            for s in ('a','b'): run(nsrun(s,'tc','filter','del','dev','wan0','egress','protocol','ip','pref','20'),2)
            for s,n in (('a','2'),('b','1')): pings.append(ping(s,f'198.{network}.0.{n}',4))
            statuses(end)
        settle=min(end,time.monotonic()+BOUNDS['settle'])
        while True:
            delay=settle-time.monotonic()
            if delay<=0: break
            inspect();bounded.remaining(end,.05);time.sleep(min(.05,delay))
        stage('capture_audit',pings=pings,transfers=transfers,udp_interruption=outage,status_samples=samples)
        reap_processes([p for p,_ in captures.values()],min(end,time.monotonic()+10),signal.SIGINT)
        counts={key:bounded.finish_capture(p,log) for key,(p,log) in captures.items()}
        underlay=audit_underlay({s:paths[s+'_wan'] for s in ('a','b')},plan,outage)
        native=transparent.audit_native({s:paths[s+'_native'] for s in ('a','b')},plan['flows'])
        for side in ('a','b'):
            if counts[side+'_wan']['captured']!=underlay[side]['packets'] or counts[side+'_native']['captured']!=native['ip_packets_each_side']:
                raise ValueError('capture file/diagnostic packet count mismatch')
        bounded.remaining(end,1)
        stage('completed',capture_counts=counts,underlay_audit=underlay,native_audit=native,capture_sha256={key:bounded.file_hash(path) for key,path in paths.items()},identities_after=owned())
    except Exception as error:
        failure=error;receipt.update(status=classify(error),error=str(error)[:4096])
    finally:
        errors=[];cleanup_end=time.monotonic()+BOUNDS['cleanup']
        try: reap_processes(processes,cleanup_end)
        except Exception as error: errors.append(str(error)[:256])
        for p,log in captures.values():
            if p.poll() is not None and p.stderr is not None and not p.stderr.closed:
                try: bounded.finish_capture(p,log)
                except Exception: pass
        try:
            if errors or any(p.poll() is None for p in processes): raise RuntimeError('original children not reaped: '+repr(errors))
            removed=transparent.cleanup_sockets(socket_owners,processes)
            if created: bounded.bounded_lab(netns_lab.cleanup,spec,state_dir,cleanup_end)
            if namespace_observation(spec)!=before: raise RuntimeError('expected namespace identity changed/residual after cleanup; never adopt/delete unjournaled names')
            receipt.update(cleanup='passed',status='passed' if failure is None else receipt.value['status'],original_children_reaped=True,removed_owned_sockets=removed,elapsed_seconds=time.monotonic()-start,terminal='explicit cancellation only')
        except Exception as error:
            failure=error;receipt.update(cleanup='failed',status='failed',cleanup_error=str(error)[:4096])
    if failure: raise RuntimeError(f'{plan["case"]} failed; inspect {receipt.path}') from failure
    return receipt.value


def reap_processes(processes:list,deadline:float,sig=signal.SIGTERM)->None:
    """One original cleanup allowance, with simultaneous notification of all owners."""
    for process in processes:
        if process.poll() is None: process.send_signal(sig)
    grace=min(deadline,time.monotonic()+5)
    for process in processes:
        if process.poll() is None:
            try: process.wait(timeout=bounded.remaining(grace,5))
            except (subprocess.TimeoutExpired,TimeoutError): break
    for process in processes:
        if process.poll() is None: process.kill()
    for process in processes:
        if process.poll() is None: process.wait(timeout=bounded.remaining(deadline,5))
    if any(p.poll() is None for p in processes): raise RuntimeError('owned process remains after original cleanup bound')


def classify(error:Exception)->str:
    if isinstance(error,bounded.CaptureBound): return 'bound_exhausted'
    return transparent.classify(error)


def source_hashes(root:Path=ROOT)->dict[str,str]:
    result=bounded.source_hashes(root)
    for name in (*HELPERS,'tools/test_rolling_native_smoke.py','docs/modules/rolling-native.md'):
        result[name]=bounded.file_hash(root/name)
    return result


def main(argv:list[str]|None=None)->int:
    argv=sys.argv[1:] if argv is None else argv
    if argv and argv[0]=='probe': return bounded.probe_main(argv[1:])
    if argv and argv[0]=='tcp-block-probe':
        if len(argv)!=2 or argv[1] not in ('192.0.2.2','192.0.2.6'): raise ValueError('owned fixed TCP probe tuple required')
        import socket
        with socket.socket() as stream:
            stream.settimeout(.3)
            try: stream.connect((argv[1],24440))
            except TimeoutError: print('TCP blocked by timeout');return 0
            raise RuntimeError('TCP unexpectedly reachable')
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--apply',action='store_true');parser.add_argument('--lab-id',default='rolling')
    parser.add_argument('--output',type=Path,default=ROOT/'work/rolling-native')
    parser.add_argument('--binary',type=Path,default=ROOT/'target/debug/l2tunnel-linux')
    parser.add_argument('--build-receipt',type=Path);parser.add_argument('--state-dir',type=Path,default=Path('/run/l2tunnel-labs'))
    cases=[f'{c}-{l}-{d}-{p}' for c in ('udp','quic') for l in ('tap','tun') for d in ('full','half') for p in ('clean','loss')]
    parser.add_argument('--carrier',choices=('udp','quic'));parser.add_argument('--only-case',choices=cases)
    parser.add_argument('--frozen-worker',help=argparse.SUPPRESS);args=parser.parse_args(argv)
    plans=[case_plan(args.lab_id,c,l,d,p) for c in ('udp','quic') for l in ('tap','tun') for d in ('full','half') for p in ('clean','loss') if (args.carrier is None or args.carrier==c) and (args.only_case is None or args.only_case==f'{c}-{l}-{d}-{p}')]
    if not plans: raise ValueError('carrier and selected case disagree')
    if not args.apply:
        print(json.dumps({'status':'dry_run','mutations':'none','cases':plans,'output':str(args.output),'binary':str(args.binary),'graceful_close':False},indent=2));return 0
    if sys.platform!='linux': raise bounded.Unsupported('native harness requires Linux')
    if args.only_case is None: raise ValueError('first native apply requires explicit --only-case')
    netns_lab.require_root()
    if args.build_receipt is None: raise ValueError('explicit immutable --build-receipt required')
    for tool in ('ip','tc','sysctl','ethtool','tcpdump','ss','ping','openssl'):
        if shutil.which(tool) is None: raise FileNotFoundError('required tool missing: '+tool)
    for path in (args.binary,args.build_receipt,*HELPERS.values()):
        if path.is_symlink() or not stat.S_ISREG(path.lstat().st_mode): raise ValueError('regular non-symlink build/helper files required')
    build=bounded.verified_build_receipt(args.build_receipt,args.binary)
    if not args.frozen_worker:
        # A successful build must cover the exact helper source loaded by this launcher.
        for name,path in HELPERS.items():
            if bounded.file_hash(path)!=build['source_sha256_after'].get(name): raise ValueError('launcher helper differs from exact build: '+name)
        if args.output.resolve().is_relative_to(args.build_receipt.resolve().parent): raise ValueError('fresh output must be outside immutable build directory')
        args.output.mkdir(mode=0o755)
    output=args.output.resolve();binary=output/'l2tunnel-native';harness=output/'rolling_native_smoke.py'
    if not args.frozen_worker:
        shutil.copyfile(args.binary,binary);binary.chmod(0o755)
        for name,path in HELPERS.items(): shutil.copyfile(path,output/Path(name).name)
        shutil.copyfile(args.build_receipt,output/'build-receipt.json');verify_helpers(build,output)
        (output/'launch-sources.json').write_text(json.dumps({name:bounded.file_hash(path) for name,path in HELPERS.items()},sort_keys=True)+'\n')
        identity=output.stat();arguments=[sys.executable,str(harness),'--apply','--lab-id',args.lab_id,'--output',str(output),'--binary',str(binary),'--build-receipt',str(output/'build-receipt.json'),'--state-dir',str(args.state_dir.resolve()),'--frozen-worker',f'{identity.st_dev}:{identity.st_ino}']
        if args.carrier: arguments+=['--carrier',args.carrier]
        if args.only_case: arguments+=['--only-case',args.only_case]
        os.execve(sys.executable,arguments,{**os.environ,'PYTHONDONTWRITEBYTECODE':'1'})
        raise RuntimeError('copied worker exec unexpectedly returned')
    identity=output.stat();expected={Path(name).name for name in HELPERS}|{'l2tunnel-native','build-receipt.json','launch-sources.json'}
    if args.frozen_worker!=f'{identity.st_dev}:{identity.st_ino}' or args.output.is_symlink() or identity.st_uid!=os.geteuid() or identity.st_mode&0o022 or args.binary.resolve()!=binary or args.build_receipt.resolve()!=output/'build-receipt.json' or {p.name for p in output.iterdir()}!=expected: raise ValueError('fresh exclusive copied worker identity/layout required')
    hashes=verify_helpers(build,output,loaded=True)
    if bounded.verified_build_receipt(output/'build-receipt.json',binary)!=build: raise ValueError('immutable build changed during copy')
    launch=output/'launch-sources.json'
    if launch.stat().st_size>bounded.RECEIPT_LIMIT or bounded.strict_json(launch.read_bytes())!=hashes: raise ValueError('launcher helper provenance mismatch')
    receipt=bounded.Receipt(output/'receipt.json',{'status':'running','cleanup':'pending','scope':'explicit W32 rolling native clean/loss finite matrix','graceful_close':False,'cases':[],'executed_helper_sha256':hashes,'binary_build_source_sha256':build['source_sha256_after'],'binary_sha256':bounded.file_hash(binary),'build_receipt_sha256':bounded.file_hash(output/'build-receipt.json')})
    results=[]
    try:
        with tempfile.TemporaryDirectory(prefix='l2t-rolling-secrets-') as directory:
            secrets=Path(directory);end=time.monotonic()+30
            def run(*argv): return bounded.command(list(argv),end)
            run(str(binary),'keygen','--private',str(secrets/'member.der'),'--public',str(secrets/'member.pub'))
            run('openssl','req','-x509','-newkey','ec','-pkeyopt','ec_paramgen_curve:P-256','-nodes','-keyout',str(secrets/'server.pem'),'-out',str(secrets/'cert.pem'),'-days','1','-subj','/CN=lab.invalid','-addext','subjectAltName=DNS:lab.invalid','-addext','basicConstraints=critical,CA:FALSE')
            run('openssl','x509','-in',str(secrets/'cert.pem'),'-outform','DER','-out',str(secrets/'cert.der'))
            run('openssl','pkcs8','-topk8','-nocrypt','-in',str(secrets/'server.pem'),'-outform','DER','-out',str(secrets/'server.der'))
            for plan in plans:
                verify_helpers(build,output,loaded=True);bounded.verified_build_receipt(output/'build-receipt.json',binary)
                result=run_case(plan,binary,harness,output,secrets,args.state_dir)
                verify_helpers(build,output,loaded=True);bounded.verified_build_receipt(output/'build-receipt.json',binary)
                results.append({'case':plan['case'],'status':result['status'],'cleanup':result['cleanup']});receipt.update(cases=results)
        receipt.update(status='passed',cleanup='passed',executed_helpers_unchanged=True)
    except Exception as error:
        receipt.update(status=classify(error),error=str(error)[:4096],cleanup='inspect_case_receipt');raise
    print(json.dumps({'status':'passed','receipt':str(receipt.path),'graceful_close':False}));return 0


if __name__=='__main__': raise SystemExit(main())
