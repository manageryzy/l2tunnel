"""Pure unprivileged rolling native harness contracts; never creates a namespace."""
import contextlib
import copy
import io
import json
from pathlib import Path
import signal
import socket
import struct
import subprocess
import tempfile
import unittest
from unittest import mock
from . import rolling_native_smoke as rolling


def record(kind=1,lane=0,direction=0,identity=0):
    session=bytes(range(1,17));vector=bytearray(1066);vector[:8]=b'L2RW\x01'+bytes([kind,0,0]);vector[8:24]=session
    struct.pack_into('!QI',vector,24,1,1+lane);vector[36]=direction;struct.pack_into('!Q',vector,40,identity)
    end=identity+1 if kind==1 else 1;seed=0 if kind==1 else (identity*2654435761)&0xffffffff
    struct.pack_into('!IIIH',vector,48,identity if kind==1 else 0,end,seed,1002)
    if kind==1:
        original=b'\0\0LX'+bytes(38)+b'z';struct.pack_into('!H',vector,64,len(original));vector[66:66+len(original)]=original
    h=b'LD\x01\x02\x02'+bytes([direction+1,0,0])+session+struct.pack('!IIQH',lane,0,identity,len(vector))+bytes(2)
    return b'\x40'+session[:8]+h+vector+b'T'*32


def packet(body,direction=0,port=24440):
    source=socket.inet_aton('192.0.2.2' if direction==0 else '192.0.2.6');target=socket.inet_aton('192.0.2.6' if direction==0 else '192.0.2.2')
    udp=struct.pack('!HHHH',port,port,len(body)+8,0)+body;ip=bytearray(b'\x45\0'+struct.pack('!H',len(udp)+20)+bytes(4)+b'\x40\x11'+bytes(2)+source+target)
    ip[10:12]=rolling.bounded.checksum(ip).to_bytes(2,'big');return bytes(12)+b'\x08\0'+ip+udp


def pcap(frames):
    result=b'\xd4\xc3\xb2\xa1'+struct.pack('<HHIIII',2,4,0,0,262144,1)
    for frame in frames: result+=struct.pack('<IIII',10,500000,len(frame),len(frame))+frame
    return result


class RollingNativeTests(unittest.TestCase):
    def plan(self,carrier='udp',layer='tun',duplex='full',profile='clean'):
        return rolling.case_plan('unit',carrier,layer,duplex,profile)

    def test_dry_run_all_sixteen_cases_has_no_mutations(self):
        with mock.patch.object(rolling.netns_lab,'require_root',side_effect=AssertionError('privileged')),mock.patch.object(rolling.netns_lab,'apply',side_effect=AssertionError('apply')),mock.patch.object(rolling.subprocess,'run',side_effect=AssertionError('command')),contextlib.redirect_stdout(io.StringIO()) as out:
            self.assertEqual(rolling.main([]),0)
        value=json.loads(out.getvalue());self.assertEqual(value['mutations'],'none');self.assertEqual(len(value['cases']),16)
        self.assertEqual(len({row['lab_id'] for row in value['cases']}),16)
        for row in value['cases']:
            self.assertEqual(row['policy'],rolling.policy());self.assertEqual(row['policy']['recovery']['window'],32);self.assertFalse(row['graceful_close'])

    def test_explicit_single_case_and_disagreeing_selection(self):
        with contextlib.redirect_stdout(io.StringIO()) as out:
            rolling.main(['--carrier','quic','--only-case','quic-tap-half-loss'])
        value=json.loads(out.getvalue());self.assertEqual(len(value['cases']),1);self.assertEqual(value['cases'][0]['netem'],{'delay_ms':35,'loss_percent':15})
        with self.assertRaises(ValueError): rolling.main(['--carrier','udp','--only-case','quic-tap-half-loss'])
        with self.assertRaises(ValueError): rolling.main(['--apply'])
        for args in [('bad','tun','full','clean'),('udp','vxlan','full','clean'),('udp','tun','bad','clean'),('udp','tun','full','adaptive')]:
            with self.assertRaises(ValueError): rolling.case_plan('unit',*args)

    def test_exact_peer_commands_use_shared_rolling_not_arq_or_fec(self):
        for carrier in ('udp','quic'):
            for layer in ('tap','tun'):
                for duplex in ('full','half'):
                    plan=self.plan(carrier,layer,duplex)
                    for side in ('a','b'):
                        argv=rolling.daemon_command(plan,side,Path('/binary'),Path('/secrets'),Path('/policy'),Path('/socket'))
                        self.assertEqual(argv[:4],['ip','netns','exec',plan['namespaces']['endpoint_'+side]])
                        for option,value in (('--record-profile','rolling'),('--rolling-policy','/policy'),('--traffic','system'),('--carrier',carrier),('--max-packet','1600'),('--compression','off')):
                            self.assertEqual(argv[argv.index(option)+1],value)
                        self.assertEqual('--udp-reverse-bind' in argv,duplex=='half');self.assertNotIn('--fec',argv)
                        self.assertEqual('--udp-cover' in argv,carrier=='udp');self.assertEqual('--quic-application-id' in argv,carrier=='quic')
                        if carrier=='udp': self.assertEqual(argv[argv.index('--udp-protection')+1],'integrity')
                        else:
                            value=argv[argv.index('--quic-application-id')+1]
                            self.assertRegex(value,r'^[0-9a-f]{32}$');self.assertEqual(bytes.fromhex(value),b'rolling-nativ-01');self.assertEqual(len(bytes.fromhex(value)),16)

    def snapshot(self,plan):
        cover='quic_like' if plan['carrier']=='udp' else 'not_applicable'
        return {'profile':'rolling-frame-v2','requested_carrier':plan['carrier'],'effective_carrier':plan['carrier'],'requested_cover':cover,'effective_cover':cover,'layer':plan['layer'],'duplex':plan['duplex'],'pipeline':'tap_system' if plan['layer']=='tap' else 'tun_drr','channels':4,'window':32,'max_payload':1000,'epoch':1,'digest':'ab'*32,'phase':'forwarding','hot_reload':False,'clean_drain':False,'tcp_window_ownership':False,'native_qualified':False,'large_window_qualified':False,'failure':None}

    def test_status_is_actual_exact_and_no_unsupported_claim_can_pass(self):
        plan=self.plan();value=self.snapshot(plan);rolling.validate_snapshot(value,plan)
        response={'version':1,'ok':True,'code':'ok','state':{'epoch':1,'phase':'forwarding','compression':'off','rolling':value}}
        rolling.validate_status(response,plan)
        for field,replacement in [('effective_carrier','tcp'),('window',8192),('pipeline','tap_system'),('native_qualified',True),('clean_drain',True),('epoch',True),('failure','TimedOut'),('digest','ab'*31),('phase','cancelled')]:
            bad=copy.deepcopy(value);bad[field]=replacement
            with self.assertRaises(ValueError,msg=field): rolling.validate_snapshot(bad,plan)
        response['state']['rolling']['phase']='authenticated';response['state']['phase']='authenticated'
        with self.assertRaises(ValueError): rolling.validate_status(response,plan)
        rolling.validate_status(response,plan,allow_authenticated=True)

    def test_fixed_netem_cannot_weaken_or_mislabel_loss(self):
        rolling.validate_netem('netem delay 35ms loss 15%',self.plan(profile='loss'))
        rolling.validate_netem('netem delay 1ms',self.plan())
        for text,plan in [('netem delay 1ms loss 15%',self.plan()),('netem delay 35ms loss 1%',self.plan(profile='loss')),('netem delay 34ms loss 15%',self.plan(profile='loss'))]:
            with self.assertRaises(ValueError): rolling.validate_netem(text,plan)

    def test_independent_literal_full_wire_and_structural_malformed_corpus(self):
        for direction in (0,1):
            for lane in (0,1):
                self.assertEqual(rolling.rolling_record(record(lane=lane,direction=direction),lane,direction)['kind'],'source')
                self.assertEqual(rolling.rolling_record(record(kind=2,lane=lane,direction=direction,identity=1),lane,direction)['kind'],'repair')
        original=record()
        for offset in (0,1,9,11,12,13,15,49,51,53,57,58,59,60,77,85,89,90,93,101,105,109,113,115,117,201):
            bad=bytearray(original);bad[offset]^=0x80
            with self.assertRaises(ValueError,msg=str(offset)): rolling.rolling_record(bytes(bad),0,0)
        for n in range(len(original)):
            with self.assertRaises(ValueError): rolling.rolling_record(original[:n],0,0)
        with self.assertRaises(ValueError): rolling.rolling_record(original+b'x',0,0)
        with self.assertRaises(ValueError): rolling.rolling_record(original,0,1)

    def test_pcap_exact_extent_mtu_precision_checksum_and_cap(self):
        data=pcap([packet(record())])
        with tempfile.TemporaryDirectory() as directory:
            path=Path(directory)/'capture.pcap';path.write_bytes(data);rows=rolling.underlay_records(path,self.plan());self.assertEqual(rows[0]['at_ns'],10500000000);self.assertEqual(rows[0]['body'],record())
            for n in (0,23,24,30,len(data)-1):
                path.write_bytes(data[:n])
                with self.assertRaises(ValueError): rolling.underlay_records(path,self.plan())
            for offset in (0,20,32,40+12,40+14+2,40+14+10):
                bad=bytearray(data);bad[offset]^=0x80;path.write_bytes(bad)
                with self.assertRaises(ValueError): rolling.underlay_records(path,self.plan())
            bad=bytearray(data);struct.pack_into('<I',bad,28,1000000);path.write_bytes(bad)
            with self.assertRaises(ValueError): rolling.underlay_records(path,self.plan())
            path.write_bytes(data)
            with mock.patch.object(rolling.bounded,'PACKET_LIMIT',1):
                with self.assertRaises(rolling.bounded.CaptureBound): rolling.underlay_records(path,self.plan())

    def controls(self):
        rows=[]
        for direction,base in ((0,100),(1,200)):
            rows.extend([{'client_port':40000,'direction':direction,'sequence':base-1,'acknowledgment':0,'flags':2,'payload_bytes':0,'at_ns':1},
                         {'client_port':40000,'direction':direction,'sequence':base,'acknowledgment':0,'flags':24,'payload_bytes':10,'at_ns':2},
                         {'client_port':40000,'direction':direction,'sequence':base+10,'acknowledgment':(200 if direction==0 else 100)+10,'flags':24,'payload_bytes':10,'at_ns':5},
                         {'client_port':40000,'direction':direction,'sequence':base+20,'acknowledgment':(200 if direction==0 else 100)+20,'flags':16,'payload_bytes':0,'at_ns':6}])
        return rows

    def test_tls_outage_requires_fresh_bytes_and_causal_new_peer_ack(self):
        rows=self.controls();outage={'start_ns':3,'end_ns':7};self.assertEqual(rolling.tls_outage_progress(rows,outage,{40000}),{40000})
        for change in ('before','late','replay','ack','syn'):
            bad=copy.deepcopy(rows)
            for row in bad:
                if change=='before' and row['at_ns']==5: row['at_ns']=2
                if change=='late' and row['at_ns']==6: row['at_ns']=8
                if change=='replay' and row['at_ns']==5: row['sequence']-=10
                if change=='ack' and row['at_ns'] in (5,6): row['acknowledgment']-=10
                if change=='syn' and row['flags']==2: row['flags']=0
            with self.assertRaises(ValueError,msg=change): rolling.tls_outage_progress(bad,outage,{40000})

    def test_peer_audit_rejects_individually_valid_but_different_rolling_traces(self):
        rows=[{**r,'protocol':'tcp','ip_bytes':60} for r in self.controls()]
        for direction in (0,1):
            for kind,identity in ((1,0),(2,1)):
                rows.append({'protocol':'udp','lane':0,'direction':direction,'body':record(kind=kind,direction=direction,identity=identity),'at_ns':4,'ip_bytes':1179})
        paths={side:Path(side) for side in ('a','b')};outage={'start_ns':3,'end_ns':7}
        with mock.patch.object(rolling,'underlay_records',side_effect=lambda path,plan:rows):
            result=rolling.audit_underlay(paths,self.plan(),outage)
            self.assertEqual(result['a']['common_rolling_records'],4)
        for change in ('tag','scope','body','nonce'):
            changed=copy.deepcopy(rows)
            for row in changed:
                if row['protocol']!='udp': continue
                body=bytearray(row['body'])
                if change=='tag': body[-1]^=1
                if change=='scope': body[1]^=1;body[17]^=1;body[61]^=1
                if change=='body' and body[58]==1: body[53+66+42]^=1
                if change=='nonce': body[48]^=0x80
                row['body']=bytes(body)
                rolling.rolling_record(row['body'],row['lane'],row['direction'])
            with mock.patch.object(rolling,'underlay_records',side_effect=lambda path,plan:rows if str(path)=='a' else changed):
                with self.assertRaises(ValueError,msg=change): rolling.audit_underlay(paths,self.plan(),outage)

    def test_peer_audit_accepts_loss_subsets_but_requires_common_source_and_repair(self):
        controls=[{**r,'protocol':'tcp','ip_bytes':60} for r in self.controls()]
        def rows(source_ids,repair_ids):
            result=copy.deepcopy(controls)
            for direction in (0,1):
                for kind,ids in ((1,source_ids),(2,repair_ids)):
                    for identity in ids:
                        result.append({'protocol':'udp','lane':0,'direction':direction,'body':record(kind=kind,direction=direction,identity=identity),'at_ns':4,'ip_bytes':1179})
            return result
        paths={side:Path(side) for side in ('a','b')};outage={'start_ns':3,'end_ns':7}
        a=rows([0,2],[1,3]);b=rows([0],[1])
        with mock.patch.object(rolling,'underlay_records',side_effect=lambda path,plan:a if str(path)=='a' else b):
            rolling.audit_underlay(paths,self.plan(),outage)
        b=rows([4],[5])
        with mock.patch.object(rolling,'underlay_records',side_effect=lambda path,plan:a if str(path)=='a' else b):
            with self.assertRaisesRegex(ValueError,'common source and repair'):
                rolling.audit_underlay(paths,self.plan(),outage)

    def test_quic_cross_capture_requires_common_opaque_bytes_in_each_direction(self):
        rows=[{'protocol':'udp','lane':lane,'direction':direction,'body':bytes([lane,direction,42]),'at_ns':4,'ip_bytes':31}
              for lane in (0,1) for direction in (0,1)]
        paths={side:Path(side) for side in ('a','b')};plan=self.plan(carrier='quic',duplex='half')
        with mock.patch.object(rolling,'underlay_records',return_value=rows):
            self.assertEqual(rolling.audit_underlay(paths,plan,None)['a']['common_opaque_datagrams'],4)
        changed=copy.deepcopy(rows);changed[0]['body']=b'other session'
        with mock.patch.object(rolling,'underlay_records',side_effect=lambda path,plan:rows if str(path)=='a' else changed):
            with self.assertRaisesRegex(ValueError,'common opaque QUIC'):
                rolling.audit_underlay(paths,plan,None)

    def test_helper_copy_hash_and_loaded_origin_cannot_be_substituted(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);source=root/'source.py';source.write_text('original');out=root/'copy';out.mkdir();target=out/'source.py';target.write_bytes(source.read_bytes())
            helpers={'tools/source.py':source};build={'source_sha256_after':{'tools/source.py':rolling.bounded.file_hash(source)}}
            with mock.patch.object(rolling,'HELPERS',helpers):
                rolling.verify_helpers(build,out)
                with self.assertRaises(ValueError): rolling.verify_helpers(build,out,loaded=True)
                target.write_text('substituted')
                with self.assertRaises(ValueError): rolling.verify_helpers(build,out)

    def test_shared_cleanup_notifies_all_before_wait_and_uses_one_deadline(self):
        calls=[]
        class Child:
            def __init__(self,name): self.name=name;self.code=None
            def poll(self): return self.code
            def send_signal(self,sig): calls.append(('signal',self.name,sig))
            def wait(self,timeout): calls.append(('wait',self.name,timeout));self.code=0;return 0
            def kill(self): calls.append(('kill',self.name));self.code=-9
        children=[Child('a'),Child('b')]
        rolling.reap_processes(children,rolling.time.monotonic()+2,signal.SIGINT)
        self.assertEqual([row[:2] for row in calls[:2]],[('signal','a'),('signal','b')]);self.assertTrue(all(child.poll()==0 for child in children))

    def test_outage_clock_brackets_reject_drift_and_regression(self):
        def anchor(mono,offset=10000000000): return {'before_mono_ns':mono,'realtime_ns':mono+offset,'after_mono_ns':mono+100}
        start,end=anchor(100),anchor(2000000100)
        value=rolling.outage_clock_interval(start,end);self.assertEqual(value['uncertainty_ns'],6000000)
        for bad in (anchor(2000000100,10010000000),anchor(50),{**end,'after_mono_ns':end['before_mono_ns']+1000001}):
            with self.assertRaises(ValueError): rolling.outage_clock_interval(start,bad)

    def test_launcher_execs_verified_copies_before_any_namespace_apply(self):
        class Handoff(Exception): pass
        with tempfile.TemporaryDirectory() as directory:
            base=Path(directory);build_dir=base/'build';build_dir.mkdir();binary=build_dir/'daemon';binary.write_bytes(b'not executed')
            helper=build_dir/'rolling_native_smoke.py';helper.write_text('# not executed')
            sources={'tools/rolling_native_smoke.py':rolling.bounded.file_hash(helper)}
            build={'status':'passed','exit_code':0,'source_stable_during_build':True,'changed_during_build':[],'source_sha256_before':sources,'source_sha256_after':sources,'binary_sha256':rolling.bounded.file_hash(binary)}
            receipt=build_dir/'build.json';receipt.write_text(json.dumps(build));out=base/'fresh'
            with mock.patch.object(rolling,'HELPERS',{'tools/rolling_native_smoke.py':helper}),mock.patch.object(rolling.netns_lab,'require_root'),mock.patch.object(rolling.netns_lab,'apply',side_effect=AssertionError('namespace before exec')) as apply,mock.patch.object(rolling.shutil,'which',return_value='/tool'),mock.patch.object(rolling.os,'execve',side_effect=Handoff) as execute:
                with self.assertRaises(Handoff): rolling.main(['--apply','--only-case','udp-tun-full-clean','--binary',str(binary),'--build-receipt',str(receipt),'--output',str(out)])
                apply.assert_not_called();argv=execute.call_args.args[1];self.assertEqual(argv[1],str(out/'rolling_native_smoke.py'));self.assertIn('--frozen-worker',argv)
            self.assertEqual((out/'l2tunnel-native').read_bytes(),binary.read_bytes())

    def test_partial_apply_residual_namespace_is_failure_not_cleanup_authority(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);plan=self.plan();before={n:None for n in plan['namespaces'].values()};after={**before,next(iter(before)):(1,2,3)}
            with mock.patch.object(rolling,'namespace_observation',side_effect=[before,after]),mock.patch.object(rolling.bounded,'bounded_lab',side_effect=RuntimeError('partial apply')) as operation,mock.patch.object(rolling.netns_lab,'cleanup',side_effect=AssertionError('must not adopt')) as cleanup:
                with self.assertRaises(RuntimeError): rolling.run_case(plan,root/'binary',root/'helper',root,root,root/'state')
                self.assertEqual(operation.call_count,1);cleanup.assert_not_called()
            receipt=json.loads((root/plan['case']/'receipt.json').read_text());self.assertEqual(receipt['cleanup'],'failed');self.assertEqual(receipt['status'],'failed')

    def test_owned_setup_failure_uses_same_journal_cleanup(self):
        with tempfile.TemporaryDirectory() as directory:
            root=Path(directory);plan=self.plan();before={n:None for n in plan['namespaces'].values()}
            with mock.patch.object(rolling,'namespace_observation',return_value=before),mock.patch.object(rolling.bounded,'bounded_lab') as operations,mock.patch.object(rolling.transparent.retained,'owned',return_value={}),mock.patch.object(rolling.bounded,'command',side_effect=RuntimeError('owned setup failure')):
                with self.assertRaises(RuntimeError): rolling.run_case(plan,root/'binary',root/'helper',root,root,root/'state')
                self.assertEqual(operations.call_count,2);self.assertIs(operations.call_args_list[0].args[0],rolling.netns_lab.apply);self.assertIs(operations.call_args_list[1].args[0],rolling.netns_lab.cleanup)
            receipt=json.loads((root/plan['case']/'receipt.json').read_text());self.assertEqual(receipt['cleanup'],'passed');self.assertNotEqual(receipt['status'],'passed')

    def test_full_underlay_audit_requires_both_direction_source_repair_and_tls(self):
        plan=self.plan();rows=[]
        for direction in (0,1):
            for kind in (1,2): rows.append({'protocol':'udp','lane':0,'direction':direction,'body':record(kind=kind,direction=direction,identity=0 if kind==1 else 1),'at_ns':5,'ip_bytes':1179})
        rows += [{**r,'protocol':'tcp','ip_bytes':60} for r in self.controls()]
        with mock.patch.object(rolling,'underlay_records',return_value=rows):
            result=rolling.audit_underlay({'a':Path('/a'),'b':Path('/b')},plan,{'start_ns':3,'end_ns':7});self.assertEqual(result['a']['rolling_repairs'],2)
        for bad in ([r for r in rows if r.get('direction')!=1],[r for r in rows if r.get('protocol')!='tcp'],[r for r in rows if r.get('body')!=record(kind=2,direction=0,identity=1)]):
            with mock.patch.object(rolling,'underlay_records',return_value=bad):
                with self.assertRaises(ValueError): rolling.audit_underlay({'a':Path('/a'),'b':Path('/b')},plan,{'start_ns':3,'end_ns':7})
        duplicate={**rows[0]};body=bytearray(duplicate['body']);body[140]^=1;duplicate['body']=bytes(body)
        with mock.patch.object(rolling,'underlay_records',return_value=rows+[duplicate]):
            with self.assertRaises(ValueError): rolling.audit_underlay({'a':Path('/a'),'b':Path('/b')},plan,{'start_ns':3,'end_ns':7})

    def test_genuine_quic_capture_does_not_invent_plaintext_or_tls(self):
        plan=self.plan('quic');rows=[{'protocol':'udp','lane':0,'direction':d,'body':b'encrypted','at_ns':1,'ip_bytes':1228} for d in (0,1)]
        with mock.patch.object(rolling,'underlay_records',return_value=rows):
            result=rolling.audit_underlay({'a':Path('/a'),'b':Path('/b')},plan,None);self.assertIn('no rolling plaintext claim',result['a']['scope']);self.assertNotIn('rolling_repairs',result['a'])

    def test_positive_negative_ping_counts_and_exit_codes_are_exact(self):
        rolling.validate_ping('1 packets transmitted, 1 received, 0% packet loss',0,True)
        rolling.validate_ping('1 packets transmitted, 0 received, 100% packet loss',1,False)
        for text,code,positive in [('1 packets transmitted, 0 received, 100% packet loss',1,True),('1 packets transmitted, 1 received, 0% packet loss',0,False),('1 packets transmitted, 0 received, 100% packet loss',2,False),('no probe',1,False)]:
            with self.assertRaises(ValueError): rolling.validate_ping(text,code,positive)

    def test_finite_bound_failure_cannot_become_success_or_protocol_failure(self):
        self.assertEqual(rolling.classify(rolling.bounded.CaptureBound('cap')),'bound_exhausted')
        self.assertEqual(rolling.classify(TimeoutError('original')),'bound_exhausted')
        self.assertEqual(rolling.classify(rolling.bounded.Unsupported('scope')),'unsupported')
        self.assertEqual(rolling.classify(OSError('tool')),'tool_failure')
        self.assertEqual(rolling.classify(ValueError('invalid data')),'failed')


if __name__=='__main__': unittest.main()
