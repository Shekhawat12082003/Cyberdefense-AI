import os
import json
import hashlib
from datetime import datetime
from pathlib import Path
from dotenv import load_dotenv

load_dotenv(dotenv_path=Path(__file__).parent.parent / '.env')

WEB3_AVAILABLE = False
try:
    from web3 import Web3
    WEB3_AVAILABLE = True
except ImportError:
    pass

LOG_FILE = os.path.join(
    os.path.dirname(os.path.dirname(__file__)), 'blockchain_log.json'
)

CORE_RPC = 'https://rpc.test2.btcs.network'
CHAIN_ID = 1114


class BlockchainLogger:
    def __init__(self):
        self.mode     = 'local'
        self.w3       = None
        self.contract = None
        self.account  = None
        self._init_web3()

    def _init_web3(self):
        if not WEB3_AVAILABLE:
            print("[INFO] Web3 not installed - using local simulation")
            return

        rpc_url          = os.getenv('ETH_RPC_URL', CORE_RPC)
        contract_address = os.getenv('CONTRACT_ADDRESS', '')
        private_key      = os.getenv('WALLET_PRIVATE_KEY', '')

        if not contract_address or not private_key:
            print("[INFO] No contract/key configured - using local simulation")
            return

        try:
            self.w3 = Web3(Web3.HTTPProvider(rpc_url, request_kwargs={'timeout': 10}))

            try:
                if not self.w3.is_connected():
                    print("[WARN] Cannot connect to Core Testnet2 - using local simulation")
                    return
            except Exception as conn_err:
                print(f"[WARN] Blockchain connection timeout: {conn_err} - using local simulation")
                return

            print(f"[OK] Connected to Core Testnet2")
            print(f"   RPC      : {rpc_url}")
            print(f"   Chain ID : {self.w3.eth.chain_id}")

            if not private_key.startswith('0x'):
                private_key = '0x' + private_key

            self.account = self.w3.eth.account.from_key(private_key)
            balance      = self.w3.eth.get_balance(self.account.address)
            balance_eth  = self.w3.from_wei(balance, 'ether')
            print(f"   Wallet   : {self.account.address}")
            print(f"   Balance  : {balance_eth:.4f} tCORE")

            if balance == 0:
                print("[WARN] Wallet has 0 tCORE - get tokens from faucet")
                return

            abi_path = os.path.join(
                os.path.dirname(os.path.dirname(__file__)),
                'blockchain', 'ThreatLogger_ABI.json'
            )

            if not os.path.exists(abi_path):
                print(f"[WARN] ABI not found at {abi_path} - using local simulation")
                return

            with open(abi_path) as f:
                abi = json.load(f)

            self.contract = self.w3.eth.contract(
                address=Web3.to_checksum_address(contract_address),
                abi=abi
            )

            total = self.contract.functions.getTotalThreats().call()
            print(f"[OK] Contract loaded!")
            print(f"   Address  : {contract_address}")
            print(f"   Threats  : {total} on-chain")
            self.mode = 'core_testnet2'

        except Exception as e:
            print(f"[WARN] Blockchain init error: {e}")
            print("   Using local simulation")

    def hash_alert(self, alert_data: dict) -> str:
        hash_data = {
            'prediction':   str(alert_data.get('prediction', '')),
            'threat_score': int(float(alert_data.get('threat_score', 0))),
            'timestamp':    str(alert_data.get('timestamp', ''))
        }
        return hashlib.sha256(
            json.dumps(hash_data, sort_keys=True).encode()
        ).hexdigest()

    def log_threat(self, alert_data: dict) -> dict:
        # Use existing hash directly if provided
        alert_hash   = alert_data.get('hash') or self.hash_alert(alert_data)
        threat_score = int(float(alert_data.get('threat_score', 0)))
        prediction   = str(alert_data.get('prediction', 'Unknown'))

        if self.mode == 'core_testnet2':
            return self._log_to_chain(alert_hash, prediction, threat_score)
        else:
            return self._log_locally(alert_hash, prediction, threat_score)

    def _log_to_chain(self, alert_hash, prediction, threat_score) -> dict:
        try:
            private_key = os.getenv('WALLET_PRIVATE_KEY', '')
            if not private_key.startswith('0x'):
                private_key = '0x' + private_key

            # Check if already logged — use multiple methods for reliability
            already_exists = False
            try:
                already_exists = self.contract.functions.verifyHash(alert_hash).call()
            except Exception as ve:
                # verifyHash failed (network/timeout) — try the public mapping getter
                try:
                    already_exists = self.contract.functions.hashExists(alert_hash).call()
                except Exception:
                    # Both checks failed — skip TX to avoid on-chain revert
                    print(f"⚠️  Could not verify hash on-chain ({ve}) — skipping TX, logging locally")
                    return self._log_locally(alert_hash, prediction, threat_score)

            if already_exists:
                print(f"ℹ️  Hash already on-chain: {alert_hash[:20]}... — skipping TX")
                return self._build_result(alert_hash, prediction, threat_score, None, None)

            nonce     = self.w3.eth.get_transaction_count(self.account.address)
            gas_price = self.w3.eth.gas_price

            tx = self.contract.functions.logThreatSimple(
                alert_hash, prediction, threat_score
            ).build_transaction({
                'chainId':  CHAIN_ID,
                'from':     self.account.address,
                'nonce':    nonce,
                'gas':      300000,
                'gasPrice': gas_price,
            })

            signed  = self.w3.eth.account.sign_transaction(tx, private_key)
            raw_tx  = signed.raw_transaction if hasattr(signed, 'raw_transaction') else signed.rawTransaction
            tx_hash = self.w3.eth.send_raw_transaction(raw_tx)

            print(f"⏳ TX sent — waiting for confirmation...")
            receipt = self.w3.eth.wait_for_transaction_receipt(tx_hash, timeout=60)

            tx_hex = receipt.transactionHash.hex()
            block  = receipt.blockNumber

            # Check if the transaction actually succeeded on-chain
            if receipt.status == 0:
                print(f"⚠️  TX reverted on-chain: {tx_hex[:20]}... — logging locally")
                return self._log_locally(alert_hash, prediction, threat_score)

            result = self._build_result(alert_hash, prediction, threat_score, tx_hex, block)

            print(f"⛓  Logged on Core Testnet2!")
            print(f"   TX    : {tx_hex[:20]}...")
            print(f"   Block : {block}")
            print(f"   View  : {result['explorer']}")

            self._save_local(result)
            return result

        except Exception as e:
            print(f"⚠️  On-chain log failed: {e}")
            print("   Falling back to local")
            return self._log_locally(alert_hash, prediction, threat_score)

    def _log_locally(self, alert_hash, prediction, threat_score) -> dict:
        result = self._build_result(
            alert_hash, prediction, threat_score,
            f"0x{alert_hash[:40]}",
            self._get_next_block(),
            mode='local_simulation',
            explorer=None
        )
        self._save_local(result)
        print(f"📝 Logged locally — hash: {alert_hash[:20]}...")
        return result

    def _build_result(self, alert_hash, prediction, threat_score,
                      tx_hash, block, mode=None, explorer=None) -> dict:
        _mode     = mode or self.mode
        _explorer = explorer
        if tx_hash and _mode == 'core_testnet2':
            _explorer = f"https://scan.test2.btcs.network/tx/{tx_hash}"
        return {
            'mode':         _mode,
            'alert_hash':   alert_hash,
            'tx_hash':      tx_hash or f"0x{alert_hash[:40]}",
            'block':        block or self._get_next_block(),
            'prediction':   prediction,
            'threat_score': threat_score,
            'timestamp':    datetime.utcnow().isoformat(),
            'explorer':     _explorer,
            'verified':     True
        }

    def _get_next_block(self) -> int:
        return 1000000 + len(self._load_logs())

    def _save_local(self, entry: dict):
        logs = self._load_logs()
        for existing in logs:
            if existing.get('alert_hash') == entry.get('alert_hash'):
                return
        logs.append(entry)
        with open(LOG_FILE, 'w') as f:
            json.dump(logs, f, indent=2)

    def _load_logs(self) -> list:
        if os.path.exists(LOG_FILE):
            try:
                with open(LOG_FILE) as f:
                    return json.load(f)
            except:
                return []
        return []

    def verify_hash(self, alert_hash: str) -> dict:
        # Check on-chain first
        if self.mode == 'core_testnet2':
            try:
                exists = self.contract.functions.verifyHash(alert_hash).call()
                if exists:
                    entry = self.contract.functions.getThreatByHash(alert_hash).call()
                    return {
                        'verified': True,
                        'source':   'core_testnet2',
                        'entry': {
                            'alert_hash':   entry[0],
                            'prediction':   entry[1],
                            'threat_score': entry[2],
                            'timestamp':    datetime.fromtimestamp(entry[3]).isoformat(),
                            'block':        None,
                            'mode':         'core_testnet2',
                            'explorer':     f"https://scan.test2.btcs.network/address/{os.getenv('CONTRACT_ADDRESS')}"
                        }
                    }
            except Exception as e:
                print(f"⚠️  On-chain verify failed: {e}")

        # Check local logs
        for log in self._load_logs():
            if log.get('alert_hash') == alert_hash:
                return {'verified': True, 'source': 'local', 'entry': log}

        return {'verified': False, 'entry': None}

    def get_all_logs(self) -> list:
        return self._load_logs()


# ── Singleton ─────────────────────────────────────────────
logger = BlockchainLogger()

def log_threat(alert_data: dict)  -> dict: return logger.log_threat(alert_data)
def verify_hash(alert_hash: str)  -> dict: return logger.verify_hash(alert_hash)
def get_all_logs()                -> list: return logger.get_all_logs()