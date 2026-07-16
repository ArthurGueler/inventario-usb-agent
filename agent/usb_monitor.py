"""Monitor physical USB connections and collapse their child PnP interfaces."""

from __future__ import annotations

import logging
import re
import threading
from collections.abc import Iterable
from datetime import datetime, timezone
from typing import Callable

from .pnp_topology import PnpProperties, safe_enumerate_pnp_properties

logger = logging.getLogger(__name__)

EventCallback = Callable[[dict], None]

_VID_RE = re.compile(r'VID_([0-9A-Fa-f]{4})', re.IGNORECASE)
_PID_RE = re.compile(r'PID_([0-9A-Fa-f]{4})', re.IGNORECASE)
_GENERIC_NAMES = {
    'usb composite device',
    'dispositivo composto usb',
    'usb input device',
    'dispositivo de entrada usb',
    'hid-compliant device',
    'dispositivo compativel com hid',
    'dispositivo compatível com hid',
}


class UsbMonitor:
    """Emit one event for each physical USB device, not for each HID interface."""

    _WMI_COLUMNS = [
        'PNPDeviceID',
        'Name',
        'Description',
        'Manufacturer',
        'Service',
        'ClassGuid',
        'PNPClass',
        'HardwareID',
        'CompatibleID',
    ]
    _DEBOUNCE_SECONDS = 1.25

    def __init__(self, on_event: EventCallback):
        self._on_event = on_event
        self._stop_event = threading.Event()
        self._thread: threading.Thread | None = None
        self._known_devices: dict[str, dict] = {}

    def start(self) -> None:
        self._stop_event.clear()
        self._thread = threading.Thread(
            target=self._watch_loop,
            name='UsbMonitorThread',
            daemon=True,
        )
        self._thread.start()
        logger.info('UsbMonitor iniciado')

    def stop(self) -> None:
        self._stop_event.set()
        if self._thread:
            self._thread.join(timeout=5)
        logger.info('UsbMonitor parado')

    def _watch_loop(self) -> None:
        try:
            import pythoncom  # type: ignore[import]
            import wmi  # type: ignore[import]
        except ImportError:
            logger.error('wmi nao disponivel - UsbMonitor nao funcionara neste ambiente')
            return

        pythoncom.CoInitialize()
        try:
            c = wmi.WMI()
            self._refresh(c, initial=True)
            watcher_connect = c.Win32_PnPEntity.watch_for('creation')
            watcher_disconnect = c.Win32_PnPEntity.watch_for('deletion')
            logger.info('WMI watchers registrados - aguardando alteracoes USB...')

            while not self._stop_event.is_set():
                changed = self._wait_for_usb_change(watcher_connect, wmi)
                changed = self._wait_for_usb_change(watcher_disconnect, wmi) or changed
                if not changed:
                    continue

                # Um unico plug gera varios eventos USB/HID. Esperar o grafo PnP
                # estabilizar evita snapshots parciais e notificacoes duplicadas.
                if self._stop_event.wait(self._DEBOUNCE_SECONDS):
                    break
                self._refresh(c)
        except Exception as exc:
            logger.exception('Falha no monitor USB: %s', exc)
        finally:
            pythoncom.CoUninitialize()

    @staticmethod
    def _wait_for_usb_change(watcher: object, wmi_module: object) -> bool:
        try:
            event = watcher(timeout_ms=500)  # type: ignore[operator]
            pnp_id = (getattr(event, 'PNPDeviceID', '') or '').upper()
            return pnp_id.startswith(('USB\\', 'HID\\'))
        except wmi_module.x_wmi_timed_out:
            return False
        except Exception as exc:
            logger.warning('Erro em watcher PnP: %s', exc)
            return False

    def _refresh(self, c: object, initial: bool = False) -> None:
        current = self._capture_snapshot(c)

        if initial:
            connected_ids = list(current)
            disconnected_ids: list[str] = []
        else:
            connected_ids = list(current.keys() - self._known_devices.keys())
            disconnected_ids = list(self._known_devices.keys() - current.keys())

        for physical_id in sorted(disconnected_ids):
            self._emit(self._known_devices[physical_id], 'disconnected')
        for physical_id in sorted(connected_ids):
            self._emit(current[physical_id], 'connected')

        self._known_devices = current
        if initial:
            logger.info(
                'Scan inicial: %d dispositivo(s) USB fisico(s) reportado(s)',
                len(current),
            )

    def _capture_snapshot(self, c: object) -> dict[str, dict]:
        entities = c.Win32_PnPEntity(self._WMI_COLUMNS)  # type: ignore[attr-defined]
        topology = safe_enumerate_pnp_properties()
        return self._build_snapshot(entities, topology)

    @classmethod
    def _build_snapshot(
        cls,
        entities: Iterable[object],
        topology: dict[str, PnpProperties],
    ) -> dict[str, dict]:
        entity_map: dict[str, object] = {}
        for entity in entities:
            pnp_id = (getattr(entity, 'PNPDeviceID', '') or '').upper()
            if pnp_id.startswith(('USB\\', 'HID\\')) and _VID_RE.search(pnp_id):
                entity_map[pnp_id] = entity

        physical_roots = {
            pnp_id for pnp_id in entity_map if cls._is_physical_usb_id(pnp_id)
        }
        grouped: dict[str, list[object]] = {root: [] for root in physical_roots}

        for pnp_id, entity in entity_map.items():
            root = cls._find_physical_root(pnp_id, topology)
            if root not in physical_roots:
                root = cls._fallback_root(pnp_id, physical_roots)
            if root in grouped:
                grouped[root].append(entity)

        snapshot: dict[str, dict] = {}
        for root_id, members in grouped.items():
            root = entity_map[root_id]
            vid, pid, serial = cls._parse_pnp_id(root_id)
            props = topology.get(root_id, PnpProperties())
            # CM_REMOVAL_POLICY_EXPECT_NO_REMOVAL: componente USB interno,
            # como Bluetooth, webcam ou leitor de cartao integrado.
            if props.removal_policy == 1:
                continue

            member_ids = {
                (getattr(member, 'PNPDeviceID', '') or '').upper()
                for member in members
            }
            interfaces = [
                cls._entity_metadata(member)
                for member in members
                if (getattr(member, 'PNPDeviceID', '') or '').upper() != root_id
            ]
            root_metadata = cls._entity_metadata(root)
            bus_description = cls._clean_text(props.bus_description)
            friendly_name = cls._best_name(bus_description, root_metadata, interfaces)

            snapshot[root_id] = {
                'vid': vid,
                'pid': pid,
                'serial': serial,
                'friendly_name': friendly_name,
                'pnp_device_id': root_id,
                'physical_instance_id': root_id,
                'container_id': props.container_id,
                'bus_description': bus_description,
                'removal_policy': props.removal_policy,
                'is_removable': props.removal_policy in (2, 3),
                'manufacturer': cls._best_value(root_metadata, interfaces, 'manufacturer'),
                'description': cls._best_value(root_metadata, interfaces, 'description'),
                'service': root_metadata.get('service'),
                'class_guid': root_metadata.get('class_guid'),
                'pnp_class': root_metadata.get('pnp_class'),
                'hardware_ids': cls._unique_values(
                    item for member in [root_metadata, *interfaces]
                    for item in member.get('hardware_ids', [])
                ),
                'compatible_ids': cls._unique_values(
                    item for member in [root_metadata, *interfaces]
                    for item in member.get('compatible_ids', [])
                ),
                'interfaces': interfaces,
                'interface_count': max(0, len(member_ids) - 1),
                'is_composite': len(member_ids) > 1,
            }
        return snapshot

    @staticmethod
    def _is_physical_usb_id(pnp_id: str) -> bool:
        parts = pnp_id.split('\\')
        return (
            len(parts) >= 3
            and parts[0] == 'USB'
            and parts[1].startswith('VID_')
            and '&MI_' not in parts[1]
        )

    @classmethod
    def _find_physical_root(
        cls,
        pnp_id: str,
        topology: dict[str, PnpProperties],
    ) -> str | None:
        current = pnp_id
        root: str | None = None
        visited: set[str] = set()
        while current and current not in visited:
            visited.add(current)
            if cls._is_physical_usb_id(current):
                root = current
            parent = topology.get(current, PnpProperties()).parent
            current = parent.upper() if parent else ''
        return root

    @classmethod
    def _fallback_root(cls, pnp_id: str, roots: set[str]) -> str | None:
        vid, pid, _ = cls._parse_pnp_id(pnp_id)
        matches = [
            root for root in roots
            if cls._parse_pnp_id(root)[:2] == (vid, pid)
        ]
        return matches[0] if len(matches) == 1 else None

    @classmethod
    def _entity_metadata(cls, entity: object) -> dict:
        return {
            'pnp_device_id': getattr(entity, 'PNPDeviceID', None),
            'friendly_name': cls._clean_text(getattr(entity, 'Name', None)),
            'description': cls._clean_text(getattr(entity, 'Description', None)),
            'manufacturer': cls._clean_text(getattr(entity, 'Manufacturer', None)),
            'service': cls._clean_text(getattr(entity, 'Service', None)),
            'class_guid': cls._clean_text(getattr(entity, 'ClassGuid', None)),
            'pnp_class': cls._clean_text(getattr(entity, 'PNPClass', None)),
            'hardware_ids': cls._list_prop(entity, 'HardwareID'),
            'compatible_ids': cls._list_prop(entity, 'CompatibleID'),
        }

    @classmethod
    def _best_name(
        cls,
        bus_description: str | None,
        root: dict,
        interfaces: list[dict],
    ) -> str | None:
        candidates = [
            bus_description,
            root.get('friendly_name'),
            root.get('description'),
            *(interface.get('friendly_name') for interface in interfaces),
        ]
        for candidate in candidates:
            if candidate and candidate.casefold() not in _GENERIC_NAMES:
                return candidate
        return next((candidate for candidate in candidates if candidate), None)

    @staticmethod
    def _best_value(root: dict, interfaces: list[dict], field: str) -> str | None:
        values = [root.get(field), *(interface.get(field) for interface in interfaces)]
        return next((value for value in values if value), None)

    @staticmethod
    def _clean_text(value: object) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        return text or None

    @staticmethod
    def _list_prop(entity: object, name: str) -> list[str]:
        raw = getattr(entity, name, None)
        if not raw:
            return []
        try:
            return [str(item) for item in raw if item]
        except TypeError:
            return [str(raw)]

    @staticmethod
    def _unique_values(values: Iterable[str]) -> list[str]:
        return list(dict.fromkeys(value for value in values if value))

    def _emit(self, device: dict, event_type: str) -> None:
        event_data = {
            **device,
            'event_type': event_type,
            'event_time': datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%S.000Z'),
        }
        logger.info(
            '%s - %s [VID:%s PID:%s interfaces:%d container:%s]',
            event_type.upper(),
            device.get('friendly_name'),
            device.get('vid'),
            device.get('pid'),
            device.get('interface_count', 0),
            device.get('container_id') or 'n/a',
        )
        self._on_event(event_data)

    @staticmethod
    def _parse_pnp_id(pnp_id: str) -> tuple[str, str, str | None]:
        vid_match = _VID_RE.search(pnp_id)
        pid_match = _PID_RE.search(pnp_id)
        parts = pnp_id.split('\\')
        serial = parts[2] if len(parts) >= 3 and '&' not in parts[2] else None
        vid = vid_match.group(1).upper() if vid_match else '0000'
        pid = pid_match.group(1).upper() if pid_match else '0000'
        return vid, pid, serial
