import json
import unittest
from pathlib import Path
from unittest.mock import patch

from backend.models import network_scorer
from backend.models.network_monitor import NetworkMonitor
from backend.utils.flow_extractor import Flow, FlowExtractor


class NetworkVerificationTests(unittest.TestCase):
    def test_flow_features_cover_trained_schema_and_extract_flags(self):
        model_info_path = (
            Path(__file__).parents[1] / 'models' / 'network_model_info.json'
        )
        model_features = json.loads(model_info_path.read_text())['features']
        flow = Flow('192.0.2.10', '192.0.2.20', 41000, 443, 'TCP')

        for index in range(10):
            packet = {
                'ip.src': '192.0.2.10' if index % 2 == 0 else '192.0.2.20',
                'ip.len': '60',
                'ip.hdr_len': '20',
                'tcp.hdr_len': '20',
                'tcp.flags': '0x001A',
                'tcp.len': '20',
                'tcp.window_size_value': '64240',
                'frame.time_epoch': str(1_800_000_000 + index / 10),
            }
            flow.add_packet(packet)

        features = flow.get_features()
        self.assertFalse(set(model_features) - features.keys())
        self.assertEqual(features['SYN Flag Count'], 10)
        self.assertEqual(features['ACK Flag Count'], 10)
        self.assertEqual(features['Fwd PSH Flags'], 5)
        self.assertEqual(features['Bwd PSH Flags'], 5)
        self.assertAlmostEqual(features['Flow Duration'], 900_000, delta=1)
        self.assertEqual(features['Init_Win_bytes_forward'], 64240)
        self.assertEqual(features['Init_Win_bytes_backward'], 64240)

    def test_tshark_packets_keep_protocol_and_ipv6_endpoints(self):
        extractor = FlowExtractor(min_packets=1)
        packet = {
            'ipv6.src': '2001:db8::10',
            'ipv6.dst': '2001:db8::20',
            'ipv6.nxt': '17',
            'udp.srcport': '53000',
            'udp.dstport': '53',
            'ipv6.plen': '40',
            'frame.time_epoch': '1800000000.0',
        }

        extractor.add_packet(packet)

        flows = extractor.get_active_flows()
        self.assertEqual(len(flows), 1)
        self.assertEqual(flows[0]['src_ip'], '2001:db8::10')
        self.assertEqual(flows[0]['dst_ip'], '2001:db8::20')
        self.assertEqual(flows[0]['protocol'], 'UDP')

    def test_model_unavailable_is_never_reported_as_verified(self):
        with patch.object(network_scorer, '_loaded', False):
            prediction = network_scorer.predict_flow({})

        self.assertEqual(prediction['prediction'], 'UNKNOWN')
        self.assertFalse(prediction['is_attack'])
        self.assertFalse(prediction['verified'])

    def test_missing_model_features_fail_closed(self):
        with (
            patch.object(network_scorer, '_loaded', True),
            patch.object(network_scorer, '_rf_model', object()),
            patch.object(network_scorer, '_features', ['required-feature']),
        ):
            prediction = network_scorer.predict_flow({})

        self.assertEqual(prediction['model'], 'feature_mismatch')
        self.assertFalse(prediction['is_attack'])
        self.assertFalse(prediction['verified'])

    def test_non_finite_model_features_fail_closed(self):
        with (
            patch.object(network_scorer, '_loaded', True),
            patch.object(network_scorer, '_rf_model', object()),
            patch.object(network_scorer, '_features', ['required-feature']),
        ):
            prediction = network_scorer.predict_flow({'required-feature': float('nan')})

        self.assertEqual(prediction['model'], 'invalid_features')
        self.assertFalse(prediction['is_attack'])
        self.assertFalse(prediction['verified'])

    def test_rule_candidate_cannot_create_confidence_without_model_features(self):
        with patch.object(network_scorer, '_loaded', False):
            prediction = network_scorer.predict_attack_type('PORT_SCAN')

        self.assertEqual(prediction['prediction'], 'UNKNOWN')
        self.assertEqual(prediction['candidate_type'], 'PORT_SCAN')
        self.assertFalse(prediction['is_attack'])
        self.assertFalse(prediction['verified'])

    def test_rule_candidate_does_not_override_trained_model_class(self):
        with (
            patch.object(network_scorer, '_loaded', True),
            patch.object(network_scorer, 'predict_flow', return_value={
                'prediction': 'BENIGN',
                'confidence': 98.0,
                'is_attack': False,
                'verified': True,
                'model': 'network_rf_dnn_ensemble',
            }),
        ):
            prediction = network_scorer.predict_attack_type('PORT_SCAN', {'feature': 1})

        self.assertEqual(prediction['prediction'], 'BENIGN')
        self.assertFalse(prediction['rule_agreement'])
        self.assertFalse(prediction['is_attack'])
        self.assertFalse(prediction['verified'])

    def test_legacy_rule_candidate_does_not_emit_confirmed_alert(self):
        class SocketRecorder:
            def __init__(self):
                self.events = []

            def emit(self, event, payload):
                self.events.append((event, payload))

        socket = SocketRecorder()
        monitor = NetworkMonitor(socket, None, None, capture_packets=False)
        from datetime import datetime
        monitor._raise_alert(
            'PORT_SCAN',
            '203.0.113.10',
            'HIGH',
            'rule candidate',
            {'dst_port': 443},
            datetime.utcnow(),
        )

        self.assertEqual(socket.events, [])
        self.assertEqual(monitor.get_alerts(), [])
        self.assertEqual(monitor.get_stats()['alerts_today'], 0)


if __name__ == '__main__':
    unittest.main()
