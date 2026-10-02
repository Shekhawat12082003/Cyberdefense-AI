"""Quick check of trained network models on disk."""
import json, os, sys
sys.path.insert(0, '.')

models_dir = os.path.join(os.path.dirname(__file__), 'models')

# Main info
info_path = os.path.join(models_dir, 'network_model_info.json')
if os.path.exists(info_path):
    info = json.load(open(info_path))
    print('network_model_info.json:')
    print(f"  version    : {info.get('version')}")
    print(f"  RF acc     : {info.get('rf_accuracy')}%")
    print(f"  DNN acc    : {info.get('dl_accuracy')}%")
    print(f"  classes    : {info.get('classes')}")
    print(f"  features   : {info.get('feature_count')}")
else:
    print('network_model_info.json: NOT FOUND')

# DNN info
dl_path = os.path.join(models_dir, 'network_dl_model_info.json')
if os.path.exists(dl_path):
    dl = json.load(open(dl_path))
    print()
    print('network_dl_model_info.json:')
    print(f"  norm       : {dl.get('norm', 'NOT SET — old model')}")
    print(f"  arch       : {dl.get('architecture')}")
    print(f"  activation : {dl.get('activation', 'not set')}")
else:
    print('network_dl_model_info.json: NOT FOUND')

print()
print('Model files:')
for fn in sorted(os.listdir(models_dir)):
    if fn.startswith('network_') and not fn.startswith('network_nsl'):
        kb = os.path.getsize(os.path.join(models_dir, fn)) / 1024
        print(f'  {fn:<47} {kb:>8.0f} KB')

# Load scorer and test
print()
print('Loading network_scorer...')
from models.network_scorer import get_status, predict_attack_type

status = get_status()
print(f"  Loaded    : {status['network_ids_loaded']}")
print(f"  Features  : {status['feature_count']}")
print(f"  DNN       : {status['dl_model']}")
print(f"  RF acc    : {status['rf_accuracy']}%")
print(f"  DNN acc   : {status['dl_accuracy']}%")
print(f"  Classes   : {status['classes']}")

print()
print('Quick prediction test:')
for atype in ['PORT_SCAN', 'BRUTE_FORCE', 'DOS', 'DDOS']:
    r = predict_attack_type(atype)
    print(f"  {atype:<15} -> {r['prediction']:<15} conf={r['confidence']:.0f}%  risk={r['risk_score']:.0f}")

print()
print('✅ Done — restart backend to activate updated models')
