# tests/test_classifier.py
import pytest
from agent.classifier import classify, classify_physical


class TestClassifyByGuid:
    def test_mouse_guid(self):
        assert classify('{4D36E96B-E325-11CE-BFC1-08002BE10318}', None) == 'mouse'

    def test_keyboard_guid(self):
        assert classify('{4D36E96A-E325-11CE-BFC1-08002BE10318}', None) == 'teclado'

    def test_webcam_guid(self):
        assert classify('{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}', None) == 'webcam'

    def test_hd_externo_guid(self):
        assert classify('{4D36E967-E325-11CE-BFC1-08002BE10318}', None) == 'hd_externo'

    def test_adaptador_usb_guid(self):
        assert classify('{36FC9E60-C465-11CF-8056-444553540000}', None) == 'adaptador_usb'

    def test_fone_guid(self):
        assert classify('{4D36E96C-E325-11CE-BFC1-08002BE10318}', None) == 'fone'

    def test_guid_case_insensitive(self):
        assert classify('{4d36e96b-e325-11ce-bfc1-08002be10318}', None) == 'mouse'


class TestClassifyByName:
    def test_mouse_by_name(self):
        assert classify(None, 'Logitech USB Mouse') == 'mouse'

    def test_keyboard_by_name(self):
        assert classify(None, 'USB Keyboard') == 'teclado'

    def test_webcam_by_name(self):
        assert classify(None, 'Integrated Webcam') == 'webcam'

    def test_headset_by_name(self):
        assert classify(None, 'USB Headset') == 'headset'

    def test_pen_drive_by_name(self):
        assert classify(None, 'SanDisk Pen Drive') == 'pen_drive'
        assert classify(None, 'Kingston Flash Drive') == 'pen_drive'

    def test_hd_externo_by_name(self):
        assert classify(None, 'WD External Hard Drive') == 'hd_externo'

    def test_impressora_by_name(self):
        assert classify(None, 'HP USB Printer') == 'impressora'

    def test_bluetooth_by_name(self):
        assert classify(None, 'Bluetooth USB Adapter') == 'adaptador_bluetooth'

    def test_wifi_by_name(self):
        assert classify(None, 'WiFi USB Dongle') == 'adaptador_rede_dongle_wifi'

    def test_audio_by_name(self):
        assert classify(None, 'USB Audio Device') == 'fone'

    def test_receiver_by_name(self):
        assert classify(None, 'Logitech USB Receiver') == 'adaptador_usb'

    def test_case_insensitive_name(self):
        assert classify(None, 'LOGITECH USB MOUSE') == 'mouse'


class TestClassifyHubsAndFallback:
    def test_root_hub_is_unknown(self):
        assert classify(None, 'USB Root Hub') == 'unknown'
        assert classify(None, 'Generic USB Hub') == 'unknown'
        assert classify(None, 'USB Composite Device') == 'unknown'

    def test_no_info_falls_back_to_peripheral(self):
        assert classify(None, None) == 'peripheral'

    def test_unrecognized_device_falls_back(self):
        assert classify(None, 'Some Unknown Widget Pro') == 'peripheral'

    def test_guid_takes_priority_over_name(self):
        # GUID de mouse, mas nome diz keyboard — GUID vence
        result = classify('{4D36E96B-E325-11CE-BFC1-08002BE10318}', 'USB Keyboard')
        assert result == 'mouse'


class TestClassifyPhysicalDevice:
    def test_gaming_mouse_wins_its_macro_keyboard_interfaces(self):
        interfaces = [
            {
                'friendly_name': 'HID-compliant mouse',
                'class_guid': '{4D36E96B-E325-11CE-BFC1-08002BE10318}',
                'compatible_ids': ['HID_DEVICE_SYSTEM_MOUSE'],
            },
            {
                'friendly_name': 'HID Keyboard Device',
                'class_guid': '{4D36E96A-E325-11CE-BFC1-08002BE10318}',
                'compatible_ids': ['HID_DEVICE_SYSTEM_KEYBOARD'],
            },
        ]
        result, source = classify_physical(
            '{36FC9E60-C465-11CF-8056-444553540000}',
            'Razer Viper Mini',
            '1532',
            [],
            interfaces,
        )
        assert result == 'mouse'
        assert source == 'child_interface'

    def test_bus_reported_keyboard_name_has_priority(self):
        interfaces = [{
            'friendly_name': 'HID-compliant consumer control device',
            'class_guid': None,
            'compatible_ids': ['HID_DEVICE_UP:000C_U:0001'],
        }]
        result, source = classify_physical(None, 'Usb KeyBoard', interfaces=interfaces)
        assert result == 'teclado'
        assert source == 'physical_name'
