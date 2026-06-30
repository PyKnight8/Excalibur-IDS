import unittest

from excalibur.detection.manager import DetectorManager


class StubDetector:
    def __init__(self):
        self.received_packets = []

    def process_packet(self, packet_info):
        self.received_packets.append(packet_info)


class DetectorManagerTest(unittest.TestCase):
    def test_process_forwards_packet_info_to_registered_detectors(self):
        first_detector = StubDetector()
        second_detector = StubDetector()
        manager = DetectorManager(
            database=None,
            detectors=[first_detector, second_detector],
        )
        packet_info = {
            "timestamp": "2026-06-08T10:00:00+00:00",
            "src_ip": "10.0.0.10",
            "dst_ip": "10.0.0.1",
            "protocol": "TCP",
            "src_port": 12345,
            "dst_port": 80,
            "packet_size": 60,
        }

        manager.process(packet_info)

        self.assertEqual(first_detector.received_packets, [packet_info])
        self.assertEqual(second_detector.received_packets, [packet_info])

    def test_register_adds_detector(self):
        detector = StubDetector()
        manager = DetectorManager(database=None, detectors=[])
        packet_info = {"src_ip": "10.0.0.10", "dst_port": 80}

        manager.register(detector)
        manager.process(packet_info)

        self.assertEqual(detector.received_packets, [packet_info])


if __name__ == "__main__":
    unittest.main()
