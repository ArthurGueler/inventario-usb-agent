from agent.pnp_topology import PnpProperties
from agent.usb_monitor import UsbMonitor


class FakePnpEntity:
    def __init__(self, pnp_id, name, class_guid=None, compatible_ids=None):
        self.PNPDeviceID = pnp_id
        self.Name = name
        self.Description = name
        self.Manufacturer = 'Test Manufacturer'
        self.Service = None
        self.ClassGuid = class_guid
        self.PNPClass = None
        self.HardwareID = []
        self.CompatibleID = compatible_ids or []


def test_composite_mouse_is_one_physical_device():
    root_id = r'USB\VID_1532&PID_008A\5&13F14556&0&7'
    mouse_usb_id = r'USB\VID_1532&PID_008A&MI_00\6&15CA8E52&0&0000'
    mouse_hid_id = r'HID\VID_1532&PID_008A&MI_00\7&1158FA72&0&0000'
    keyboard_usb_id = r'USB\VID_1532&PID_008A&MI_01\6&15CA8E52&0&0001'
    keyboard_hid_id = r'HID\VID_1532&PID_008A&MI_01&COL01\7&291C86B7&0&0000'

    entities = [
        FakePnpEntity(root_id, 'USB Composite Device'),
        FakePnpEntity(mouse_usb_id, 'USB Input Device'),
        FakePnpEntity(
            mouse_hid_id,
            'HID-compliant mouse',
            '{4D36E96B-E325-11CE-BFC1-08002BE10318}',
            ['HID_DEVICE_SYSTEM_MOUSE'],
        ),
        FakePnpEntity(keyboard_usb_id, 'USB Input Device'),
        FakePnpEntity(
            keyboard_hid_id,
            'HID Keyboard Device',
            '{4D36E96A-E325-11CE-BFC1-08002BE10318}',
            ['HID_DEVICE_SYSTEM_KEYBOARD'],
        ),
    ]
    topology = {
        root_id: PnpProperties(
            parent=r'USB\ROOT_HUB30\4&26383A98&0&0',
            container_id='{DC5C41B2-3D19-11F1-9CB8-806E6F6E6963}',
            bus_description='Razer Viper Mini',
        ),
        mouse_usb_id: PnpProperties(parent=root_id),
        mouse_hid_id: PnpProperties(parent=mouse_usb_id),
        keyboard_usb_id: PnpProperties(parent=root_id),
        keyboard_hid_id: PnpProperties(parent=keyboard_usb_id),
    }

    snapshot = UsbMonitor._build_snapshot(entities, topology)

    assert list(snapshot) == [root_id]
    device = snapshot[root_id]
    assert device['friendly_name'] == 'Razer Viper Mini'
    assert device['container_id'] == '{DC5C41B2-3D19-11F1-9CB8-806E6F6E6963}'
    assert device['interface_count'] == 4
    assert device['is_composite'] is True
    assert len(device['interfaces']) == 4


def test_two_physical_devices_with_same_vid_pid_are_not_grouped_together():
    root_one = r'USB\VID_1234&PID_5678\5&AAAA&0&1'
    root_two = r'USB\VID_1234&PID_5678\5&BBBB&0&2'
    entities = [
        FakePnpEntity(root_one, 'USB Mouse'),
        FakePnpEntity(root_two, 'USB Mouse'),
    ]

    snapshot = UsbMonitor._build_snapshot(entities, {})

    assert set(snapshot) == {root_one, root_two}


def test_internal_usb_component_is_ignored_by_removal_policy():
    root_id = r'USB\VID_8087&PID_0026\5&13F14556&0&10'
    entities = [FakePnpEntity(root_id, 'Intel Wireless Bluetooth')]
    topology = {
        root_id: PnpProperties(
            parent=r'USB\ROOT_HUB30\4&26383A98&0&0',
            removal_policy=1,
        ),
    }

    assert UsbMonitor._build_snapshot(entities, topology) == {}


def test_refresh_publishes_complete_snapshot(monkeypatch):
    root_id = r'USB\VID_1234&PID_5678\SERIAL001'
    device = {'vid': '1234', 'pid': '5678', 'pnp_device_id': root_id}
    snapshots = []
    monitor = UsbMonitor(lambda event: None, on_snapshot=snapshots.append)
    monkeypatch.setattr(monitor, '_capture_snapshot', lambda _c: {root_id: device})

    monitor._refresh(object(), initial=True)

    assert snapshots == [[device]]
    assert monitor.current_devices() == [device]
