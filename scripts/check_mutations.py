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
    if text.count(old) != 1:
        raise ValueError(('mutation anchor count', old, text.count(old)))
    return text.replace(old,new,1)

def mutate(dst, name):
    p=dst/'iip/main.c';s=p.read_text()
    timer='IIP_CONF_TCP_MSL_SEC * 1000U * 2 < w->now_ms - II_TCP_CONN(i).time_wait_ts_ms'
    if name == 'p9_invalid_ack':
        s=replace_once(s, '*out_of_order_p = out_of_order;',
                       'if (ii_tcp_hdr_has_ack(w, pb_id)) { out_of_order = 0; valid_ack = 2; } /* injected defect */\n\t*out_of_order_p = out_of_order;')
    elif name == 'p9_seq_unsigned':
        s=replace_once(s, 'if (b - a >= 0x80000000)', 'if (b <= a) /* injected defect */')
    elif name == 'p9_option_overrun':
        s=replace_once(s, 'if (tcp_opt[l + 1] > tcp_opt_len - l)',
                       'if (false) /* injected defect: missing option bound */')
    elif name == 'p9_release_partial':
        s=replace_once(s, '<= II_TCP_CONN(conn_id).sent_seq - (II_PB(pb_id).tcp.seq + (ii_tcp_hdr_has_syn(w, pb_id) ? 1 : 0) + (ii_tcp_hdr_has_fin(w, pb_id) ? 1 : 0) + II_PB(pb_id).tcp.payload_len)',
                       '< II_TCP_CONN(conn_id).sent_seq - II_PB(pb_id).tcp.seq /* injected defect: release partially ACKed descriptor */')
    elif name == 'p9_duplicate_delivery':
        s=replace_once(s, '\n\t\t\tIIP_OPS_TCP_PAYLOAD();',
                       '\n\t\t\tIIP_OPS_TCP_PAYLOAD();\n\t\t\tIIP_OPS_TCP_PAYLOAD(); /* injected defect */')
    elif name == 'p9_fin_sequence':
        s=replace_once(s, '+ (II_PB(II_TCP_CONN(conn_id).tx_ring.slot[slot_idx]).tcp.flags & II_TCP_FLAG_FIN ? 1 : 0)',
                       '+ 0 /* injected defect: FIN consumes no sequence space */')
    elif name == 'p9_rto_backoff':
        s=replace_once(s, 'II_TCP_CONN(conn_id).rto_ms *= 2;',
                       'II_TCP_CONN(conn_id).rto_ms *= 1; /* injected defect */')
    elif name == 'p9_zero_window':
        s=replace_once(s, 'if (!ii_tcp_rx_window(w, conn_id)) {',
                       'if (!ii_tcp_rx_window(w, conn_id)) { return IIP_ERR_OK; /* injected defect */')
    elif name == 'p9_invalid_sack':
        s=replace_once(s, 'if (ii_seq_ordered(sle, sre)) {',
                       'if (sle != sre) { /* injected defect: accept reversed block */')
    elif name == 'p9_missing_callback':
        s=replace_once(s, 'IIP_OPS_TCP_STATE_CLOSE_WAIT();',
                       'iip_ret_int = 0; /* injected defect: suppress EOF callback */')
    elif name=='timewait_equal': s=replace_once(s,timer,timer.replace(' < ',' <= '))
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
    elif name in ('checksum_disabled', 'oracle_checksum_disabled'):
        a=s.index('static enum iip_rc ii_tcp_rx_csum_check');b=s.index('\n}',a)
        chunk=s[a:b];s=s[:a]+replace_once(chunk,'return ii_ipv4_l4_input__csum_with_pseudo(w, pb_id, opaque);','return IIP_ERR_OK; /* injected defect */')+s[b:]
    elif name=='oracle_payload_suppressed':
        s=replace_once(s, '\n\t\t\tIIP_OPS_TCP_PAYLOAD();',
                       '\n\t\t\tiip_ret_int = 0; /* injected defect: suppress native delivery */')
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
 ('p9_invalid_ack','TCP-SEQ-00000001-ACKS','FAIL','target-defect'),
 ('p9_seq_unsigned','TCP-SEQ-FFFFFFFE-RETRANSMIT','FAIL','target-defect'),
 ('p9_option_overrun','MAL-TCP-OPTION-OVERRUN','FAIL','target-defect'),
 ('p9_release_partial','TCP-SEQ-00000001-ACKS','FAIL','target-defect'),
 ('p9_duplicate_delivery','ORACLE-TCP-DUPLICATE','FAIL','target-defect'),
 ('p9_fin_sequence','TCP-SEQ-FFFFFFFF-FIN','FAIL','target-defect'),
 ('p9_rto_backoff','MUST-19','FAIL','target-defect'),
 ('p9_zero_window','TCP-SEQ-00000001-ZERO-WINDOW','FAIL','target-defect'),
 ('p9_invalid_sack','MUTATION-SACK-INVALID','FAIL','target-defect'),
 ('p9_missing_callback','MUTATION-EOF-CALLBACK','FAIL','target-defect'),
 ('oracle_checksum_disabled','ORACLE-TCP-CHECKSUM','FAIL','target-defect'),
 ('oracle_payload_suppressed','ORACLE-TCP-STREAM','FAIL','target-defect'),
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
    return run_case(dst/'harness', out, label, case)

def run_case(binary, out, label, case):
    (out/(label+'.json')).unlink(missing_ok=True)
    with (out/(label+'.tap')).open('w') as tap, (out/(label+'.log')).open('w') as log:
        r=run_command([str(binary),'--case',case,'--json',str(out/(label+'.json'))],stdout=tap,stderr=log,timeout=40)
    j=json.loads((out/(label+'.json')).read_text())
    if (len(j['cases']) != 1 or j['cases'][0]['id'] != case or
            j['exit_code'] != r.returncode):
        raise ValueError('inconsistent result report')
    status = j['cases'][0]['status']
    if status not in ('PASS', 'FAIL', 'SKIP', 'NOT_APPLICABLE', 'DEVIATION', 'INCONCLUSIVE', 'ERROR'):
        raise ValueError('unknown case status: ' + status)
    if status == 'FAIL' and r.returncode != 1:
        raise ValueError('failure is not a normal assertion result')
    execution = j['cases'][0].get('execution')
    if execution != 'normal':
        raise ValueError('case did not complete normally: execution=' + str(execution))
    return status,r.returncode

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--output',default='artifacts/mutations')
    ap.add_argument('--phase9', action='store_true', help='run the ten Phase 9 target defects')
    ap.add_argument('--experiment', action='append', choices=[e[0] for e in EXPERIMENTS],
                    help='select an experiment; repeat to select several (default: all)')
    args=ap.parse_args()
    selected = [e for e in EXPERIMENTS
                if (not args.phase9 or e[0].startswith('p9_'))
                and (not args.experiment or e[0] in args.experiment)]
    if not selected:
        ap.error('no experiments selected')
    out=Path(args.output).resolve();out.mkdir(parents=True,exist_ok=True)
    results=[]
    for name,case,expected,kind in selected:
        stage = 'baseline'
        baseline = None
        base_rc = None
        (out / (name + '.patch')).unlink(missing_ok=True)
        try:
            with tempfile.TemporaryDirectory(prefix='iip-mutation-') as tmp:
                dst=Path(tmp)
                for f in FILES:
                    (dst/f).parent.mkdir(parents=True,exist_ok=True);shutil.copy2(ROOT/f,dst/f)
                baseline,base_rc=run(dst,out,name+'-baseline',case)
                if baseline != 'PASS' or base_rc != 0:
                    raise ValueError((name, 'baseline not passing', baseline, base_rc))
                stage = 'mutation'
                mutate(dst,name)
                for f in ('iip/main.c','test_tcp_window.h'):
                    if (dst/f).read_bytes() != (ROOT/f).read_bytes():
                        import difflib
                        (out/(name+'.patch')).write_text(''.join(difflib.unified_diff((ROOT/f).read_text().splitlines(True),(dst/f).read_text().splitlines(True),fromfile=f,tofile=f)))
                stage = 'mutant'
                actual,rc=run(dst,out,name,case)
                ok=actual==expected and (rc==0 if expected=='PASS' else rc!=0)
                results.append(dict(experiment=name,case=case,kind=kind,expected=expected,actual=actual,exit_code=rc,baseline=baseline,baseline_exit_code=base_rc,
                                    outcome=('detected' if actual == 'FAIL' else 'survived' if actual == 'PASS' else 'unresolved') if kind == 'target-defect' else 'control',ok=ok))
                print(name,actual,'OK' if ok else 'UNEXPECTED',flush=True)
        except (OSError, subprocess.SubprocessError, ValueError, KeyError, IndexError, TypeError, AssertionError) as error:
            results.append(dict(experiment=name, case=case, kind=kind, expected=expected,
                                actual='ERROR', stage=stage, error=str(error), baseline=baseline,
                                baseline_exit_code=base_rc, outcome='invalid-baseline' if stage == 'baseline' else 'infrastructure-error', ok=False))
            print(name, 'ERROR', str(error), flush=True)
        finally:
            temporary = out / 'summary.json.tmp'
            temporary.write_text(json.dumps(results, indent=2) + '\n')
            temporary.replace(out / 'summary.json')
    return 0 if all(x['ok'] for x in results) else 1

if __name__=='__main__': raise SystemExit(main())
