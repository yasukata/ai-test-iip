#!/usr/bin/env python3
"""Check both allowed counterexamples and deliberately broken isolated copies."""
import argparse
import json
from pathlib import Path
import shutil
import subprocess
import tempfile
import sys

ROOT=Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "tests"))
from process_support import run_command
# Include every harness module when building an isolated mutated copy.
FILES = sorted(p.name for p in ROOT.iterdir() if p.suffix in ('.c', '.h')) + ['iip/main.c']

def replace_once(text, old, new):
    assert text.count(old)==1, (old,text.count(old))
    return text.replace(old,new,1)

def mutate(dst, name):
    p=dst/'iip/main.c';s=p.read_text()
    timer='IIP_CONF_TCP_MSL_SEC * 1000U * 2 < w->now_ms - II_TCP_CONN(i).time_wait_ts_ms'
    if name=='timewait_equal': s=replace_once(s,timer,timer.replace(' < ',' <= '))
    elif name=='timewait_early': s=replace_once(s,timer,timer.replace('* 2 <','* 1 <'))
    elif name=='rtt_frozen': s=replace_once(s,'II_TCP_CONN(conn_id).rtt.srtt = nticks;','II_TCP_CONN(conn_id).rtt.srtt = 0; /* injected defect */')
    elif name=='flow_rwnd_unlimited':
        s=replace_once(s,'uint32_t flow_win = (uint32_t) II_TCP_CONN(conn_id).peer_win << II_TCP_CONN(conn_id).ws;',
                       'uint32_t flow_win = UINT32_MAX; /* injected defect */')
    elif name=='flow_cwnd_unlimited':
        s=replace_once(s,'uint32_t cc_win = (uint32_t) II_TCP_CONN(conn_id).cc.win * II_TCP_CONN(conn_id).mss;',
                       'uint32_t cc_win = UINT32_MAX; /* injected defect */')
    elif name=='flow_ca_frozen':
        s=replace_once(s,'II_TCP_CONN(conn_id).cc.win = (II_TCP_CONN(conn_id).cc.win < 65535U ? II_TCP_CONN(conn_id).cc.win + 1 : 65535U);',
                       '/* injected defect: no congestion avoidance growth */')
    elif name=='flow_loss_window_two':
        s=replace_once(s,'II_TCP_CONN(conn_id).cc.win = 1;\n\tII_TCP_CONN(conn_id).cc.acked_bytes = 0;',
                       'II_TCP_CONN(conn_id).cc.win = 2; /* injected defect */\n\tII_TCP_CONN(conn_id).cc.acked_bytes = 0;')
    elif name.startswith('life_'):
        a=s.index('static enum iip_rc ii_tcp_conn_close_check(')
        b=s.index('\n}',a)
        chunk=s[a:b]
        if name=='life_missing_close_callback':
            chunk=replace_once(chunk,'IIP_OPS_TCP_CLOSED();','iip_ret_int = 0; /* injected defect */')
        elif name=='life_retained_connection':
            chunk=replace_once(chunk,'ii_free_tcp_conn(&w->tcp_conns, conn_id);','/* injected defect: retained connection slot */')
        elif name=='life_retained_sent':
            chunk=replace_once(chunk,'for (i = 0; i < cnt; i++) {','for (i = 0; i < cnt; i++) {\n                            if (j == 2) continue; /* injected defect */')
        else: raise ValueError(name)
        s=s[:a]+chunk+s[b:]
    elif name=='checksum_disabled':
        a=s.index('static enum iip_rc ii_tcp_rx_csum_check');b=s.index('\n}',a)
        chunk=s[a:b];s=s[:a]+replace_once(chunk,'return ii_ipv4_l4_input__csum_with_pseudo(w, pb_id, opaque);','return IIP_ERR_OK; /* injected defect */')+s[b:]
    elif name=='missing_ts_drop':
        anchor='static bool ii_tcp_paws(IIP_MEM_P w, IIP_TCP_CONN_P conn_id, II_PB_P pb_id)\n{'
        code='\n    if ((II_TCP_CONN(conn_id).flags & II_TCP_CONN_FLAGS_OPT_SET_TS) && !(II_PB(pb_id).tcp.info_flags & II_PB_FLAGS_TCP_OPT_HAS_TS) && !(II_PB(pb_id).tcp.flags & (II_TCP_FLAG_SYN | II_TCP_FLAG_RST))) return true;'
        s=replace_once(s,anchor,anchor+code)
    elif name.startswith('ack_'):
        # Observer counterexample: synthetic ACK scheduled by fake-clock time.
        # This is NOT counted as a mutation of the target TCP implementation.
        delay=int(name.split('_')[1]);p=dst/'test_tcp_window.h';s=p.read_text()
        a=s.index('static enum result test_delayed_ack_limit');b=s.index('static enum result test_window_shrink_robustness',a);chunk=s[a:b]
        needle='fixture_deliver(&f, build_tcp_packet(&spec, &f.state));'
        chunk=replace_once(chunk,needle,needle+'\n    void *scheduled = fixture_packet(&f, 0, 0, 0);\n    assert(scheduled);\n    free_output(&f.state);')
        needle='for (elapsed = 0; elapsed < 500; elapsed++) {'
        chunk=replace_once(chunk,needle,needle+f'\n        if (elapsed == {delay}) f.state.out[f.state.out_cnt++] = scheduled;')
        s=s[:a]+chunk+s[b:]
    else: raise ValueError(name)
    p.write_text(s)

EXPERIMENTS=[
 ('life_missing_close_callback','TCP-LIFE-RST-AFTER-RTO','FAIL','target-defect'),
 ('life_retained_connection','TCP-LIFE-REPEAT-RESET','FAIL','target-defect'),
 ('life_retained_sent','TCP-LIFE-RST-AFTER-RTO','FAIL','target-defect'),
 ('timewait_equal','MUST-13','PASS','target-permitted'),
 ('timewait_early','MUST-13','FAIL','target-defect'),
 ('rtt_frozen','TCP-RTT-1','FAIL','target-defect'),
 ('checksum_disabled','MUST-3','FAIL','target-defect'),
 ('missing_ts_drop','ROBUST-BOUNDARY-CONTROL','PASS','target-permitted'),
 ('ack_495','MUST-40','PASS','observer-counterexample'),
 ('ack_499','MUST-40','PASS','observer-counterexample'),
 ('ack_500','MUST-40','FAIL','observer-counterexample'),
 ('flow_rwnd_unlimited','TCP-FLOW-RWND-LIMIT','FAIL','target-defect'),
 ('flow_cwnd_unlimited','TCP-FLOW-CWND-LIMIT','FAIL','target-defect'),
 ('flow_ca_frozen','TCP-FLOW-CA-GROWTH','FAIL','target-defect'),
 ('flow_loss_window_two','TCP-FLOW-RTO-RESPONSE','FAIL','target-defect'),
]

def run(dst,out,label,case):
    (out/(label+'.json')).unlink(missing_ok=True)
    with (out/(label+'.build.log')).open('w') as log:
        run_command(['cc','-std=gnu11','-O1','-g','-Wall','-Wextra','-o',str(dst/'harness'),str(dst/'main.c')],stdout=log,stderr=subprocess.STDOUT,check=True,timeout=60)
    with (out/(label+'.tap')).open('w') as tap, (out/(label+'.log')).open('w') as log:
        r=run_command([str(dst/'harness'),'--case',case,'--json',str(out/(label+'.json'))],stdout=tap,stderr=log,timeout=40)
    j=json.loads((out/(label+'.json')).read_text())
    if (len(j['cases']) != 1 or j['cases'][0]['id'] != case or
            j['exit_code'] != r.returncode):
        raise ValueError('inconsistent result report')
    return j['cases'][0]['status'],r.returncode

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='artifacts/mutations')
    ap.add_argument('--experiment', action='append', choices=[e[0] for e in EXPERIMENTS],
                    help='select an experiment; repeat to select several (default: all)')
    args=ap.parse_args()
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    results=[]
    for name,case,expected,kind in EXPERIMENTS:
        if args.experiment and name not in args.experiment:
            continue
        stage = 'baseline'
        try:
            with tempfile.TemporaryDirectory(prefix='iip-mutation-') as tmp:
                dst=Path(tmp)
                for f in FILES:
                    (dst/f).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/f,dst/f)
                baseline,base_rc=run(dst,out,name+'-baseline',case)
                assert baseline=='PASS' and base_rc==0, (name,'baseline not passing',baseline,base_rc)
                stage = 'mutation'
                mutate(dst,name)
                for f in ('iip/main.c','test_tcp_window.h'):
                    if (dst/f).read_bytes() != (ROOT/f).read_bytes():
                        import difflib
                        (out/(name+'.patch')).write_text(''.join(difflib.unified_diff((ROOT/f).read_text().splitlines(True),(dst/f).read_text().splitlines(True),fromfile=f,tofile=f)))
                actual,rc=run(dst,out,name,case)
                ok=actual==expected and (rc==0 if expected=='PASS' else rc!=0)
                results.append(dict(experiment=name,case=case,kind=kind,expected=expected,actual=actual,exit_code=rc,ok=ok))
                print(name,actual,'OK' if ok else 'UNEXPECTED',flush=True)
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError, AssertionError) as error:
            results.append(dict(experiment=name, case=case, kind=kind, expected=expected,
                                actual='ERROR', stage=stage, error=str(error), ok=False))
            print(name, 'ERROR', str(error), flush=True)
        finally:
            temporary = out / 'summary.json.tmp'
            temporary.write_text(json.dumps(results, indent=2) + '\n')
            temporary.replace(out / 'summary.json')
    return 0 if all(x['ok'] for x in results) else 1

if __name__=='__main__': raise SystemExit(main())
