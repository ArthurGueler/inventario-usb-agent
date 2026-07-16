# agent/classifier.py
"""
Classifica dispositivos USB com base em Class GUID, CompatibleIDs e nome amigável.
Os valores de device_type correspondem EXATAMENTE ao DeviceType union em src/types/index.ts.

Ordem de prioridade:
  1. CompatibleIDs (HID usage — mais preciso para mouses, teclados, headsets HID)
  2. PNP Class GUID (para dispositivos com driver de classe dedicado)
  3. Heurística por nome amigável (fallback via substring)
  4. Fallback global: 'peripheral' ou 'unknown'
"""

# ─── 1a. Mapeamento CompatibleID HID → device_type ──────────────────────────
# Fonte: HID Usage Tables (https://usb.org/document-library/hid-usage-tables)
# Win32_PnPEntity.CompatibleID[] de dispositivos HID\ contém strings como:
#   "HID_DEVICE_SYSTEM_MOUSE", "HID_DEVICE_UP:0001_U:0002", etc.

HID_COMPATIBLE_ID_MAP: dict[str, str] = {
    # Strings nominais reportadas pelo driver HID do Windows
    'HID_DEVICE_SYSTEM_MOUSE':          'mouse',
    'HID_DEVICE_SYSTEM_KEYBOARD':       'teclado',
    'HID_DEVICE_SYSTEM_GAME_MOUSE':     'mouse',
    'HID_DEVICE_SYSTEM_CONTROL':        'peripheral',  # power/sleep buttons

    # Usage Page 0x01 (Generic Desktop Controls)
    'HID_DEVICE_UP:0001_U:0002':        'mouse',       # Mouse
    'HID_DEVICE_UP:0001_U:0004':        'peripheral',  # Joystick
    'HID_DEVICE_UP:0001_U:0005':        'peripheral',  # Gamepad
    'HID_DEVICE_UP:0001_U:0006':        'teclado',     # Keyboard
    'HID_DEVICE_UP:0001_U:0007':        'teclado',     # Keypad
    'HID_DEVICE_UP:0001_U:0080':        'peripheral',  # System Control

    # Usage Page 0x0C (Consumer Devices — headsets com botões, controles de mídia)
    'HID_DEVICE_UP:000C_U:0001':        'headset',     # Consumer Control

    # Usage Page 0x0B (Telephony Device — headsets VoIP)
    'HID_DEVICE_UP:000B_U:0001':        'headset',     # Phone

    # Usage Page 0x03 (VR Controls)
    'HID_DEVICE_UP:0003_U:0001':        'peripheral',  # VR Headset controller

    # Usage Page 0xFF (Vendor Defined)
    # Não mapeamos — pode ser qualquer coisa
}


# ─── 1b. Mapeamento CompatibleID USB class → device_type ─────────────────────
# Win32_PnPEntity.CompatibleID[] de dispositivos USB\ contém USB class codes:
#   "USB\Class_03&SubClass_01&Prot_01", "USB\Class_08", etc.
# Usamos startswith para cobrir variantes com subcódigos adicionais.
# Ordem: mais específico primeiro.

USB_CLASS_COMPAT_PREFIXES: list[tuple[str, str]] = [
    # HID class (03) — SubClass 01 = Boot Interface
    ('USB\\CLASS_03&SUBCLASS_01&PROT_01', 'teclado'),    # HID Boot Keyboard
    ('USB\\CLASS_03&SUBCLASS_01&PROT_02', 'mouse'),      # HID Boot Mouse
    # Mass Storage class (08) — default pen_drive; nome amigável sobrescreve para hd_externo se necessário
    ('USB\\CLASS_08', 'pen_drive'),
    # Video class (0E) — webcams
    ('USB\\CLASS_0E', 'webcam'),
    # Audio class (01)
    ('USB\\CLASS_01', 'fone'),
    # Printer class (07)
    ('USB\\CLASS_07', 'impressora'),
    # CDC Communications (02) — adaptadores de rede USB
    ('USB\\CLASS_02', 'adaptador_rede_usb'),
    # Wireless Controller (E0) SubClass 01 Prot 01 = Bluetooth
    ('USB\\CLASS_E0&SUBCLASS_01&PROT_01', 'adaptador_bluetooth'),
]


# ─── 2. Mapeamento PNP Class GUID → device_type ──────────────────────────────
# Fonte: Win32_PnPEntity.ClassGuid

PNP_CLASS_MAP: dict[str, str] = {
    '{4D36E96C-E325-11CE-BFC1-08002BE10318}': 'fone',           # Media (placa de som, headset USB com audio class)
    '{4D36E96B-E325-11CE-BFC1-08002BE10318}': 'mouse',          # Mouse (driver dedicado)
    '{4D36E96F-E325-11CE-BFC1-08002BE10318}': 'mouse',          # HID-compliant mouse (classe HID filtrada)
    '{4D36E96A-E325-11CE-BFC1-08002BE10318}': 'teclado',        # Keyboard (driver dedicado)
    '{6BDD1FC6-810F-11D0-BEC7-08002BE2092F}': 'webcam',         # Image (câmeras, scanners de imagem)
    '{4D36E967-E325-11CE-BFC1-08002BE10318}': 'hd_externo',     # DiskDrive (HDs, pendrives com chip de armazenamento)
    '{36FC9E60-C465-11CF-8056-444553540000}': 'adaptador_usb',  # USB (hubs, adaptadores genéricos)
    '{4D36E972-E325-11CE-BFC1-08002BE10318}': 'adaptador_rede', # Net (adaptadores de rede USB)
    '{EEC5AD98-8080-425F-922A-DABF3DE3F69A}': 'pen_drive',      # WPD (Windows Portable Devices — pendrives/MTP)
    '{4D36E965-E325-11CE-BFC1-08002BE10318}': 'hd_externo',     # CDROM (drives externos)
    # NOTA: {745A17A0...} (HID genérico) NÃO está aqui — usa CompatibleIDs para precisão
}


# ─── 3. Heurísticas por nome amigável ────────────────────────────────────────
# Ordem importa: keywords mais específicos primeiro

NAME_HEURISTICS: list[tuple[str, str]] = [
    # Periféricos de áudio
    ('headset',      'headset'),
    ('headphone',    'fone'),
    ('earphone',     'fone'),
    ('earbuds',      'fone'),
    ('fone',         'fone'),
    ('speaker',      'fone'),
    ('caixa de som', 'fone'),
    ('áudio',        'fone'),
    ('audio',        'fone'),
    ('sound',        'fone'),
    ('microphone',   'headset'),
    ('microfone',    'headset'),

    # Vídeo / câmera
    ('webcam',       'webcam'),
    ('web cam',      'webcam'),
    ('camera',       'webcam'),
    ('câmera',       'webcam'),
    ('capture',      'webcam'),

    # Apontadores
    ('mouse',        'mouse'),
    ('trackball',    'mouse'),
    ('trackpad',     'mouse'),
    ('touchpad',     'mouse'),

    # Teclados
    ('keyboard',     'teclado'),
    ('teclado',      'teclado'),
    ('keypad',       'teclado'),

    # Armazenamento — pen drives primeiro (mais específico)
    ('pen drive',    'pen_drive'),
    ('pendrive',     'pen_drive'),
    ('flash drive',  'pen_drive'),
    ('flash disk',   'pen_drive'),
    ('flash',        'pen_drive'),
    ('mass storage', 'pen_drive'),   # "USB Mass Storage Device" = pen drive genérico
    ('usb disk',     'pen_drive'),
    ('usb drive',    'pen_drive'),
    # HDs externos têm marcas/keywords distintas
    ('external',     'hd_externo'),
    ('portable',     'hd_externo'),
    ('seagate',      'hd_externo'),
    ('western digital', 'hd_externo'),
    (' wd ',         'hd_externo'),
    ('toshiba',      'hd_externo'),
    ('disk',         'hd_externo'),
    ('storage',      'hd_externo'),

    # Impressão/digitalização
    ('printer',      'impressora'),
    ('impressora',   'impressora'),
    ('print',        'impressora'),
    ('scanner',      'scanner'),
    ('scan',         'scanner'),
    ('multifuncional', 'impressora'),
    ('multifunction', 'impressora'),

    # Rede
    ('ethernet',     'adaptador_rede_usb'),
    ('lan ',         'adaptador_rede_usb'),
    ('rndis',        'adaptador_rede_usb'),
    ('wifi',         'adaptador_rede_dongle_wifi'),
    ('wi-fi',        'adaptador_rede_dongle_wifi'),
    ('wireless',     'adaptador_rede_dongle_wifi'),
    ('wlan',         'adaptador_rede_dongle_wifi'),
    ('bluetooth',    'adaptador_bluetooth'),
    ('receiver',     'adaptador_usb'),
    ('receptor',     'adaptador_usb'),

    # Vídeo/monitor
    ('monitor',      'monitor_peripheral'),
    ('display',      'monitor_peripheral'),
    ('hdmi',         'cabo_hdmi'),
    ('displaylink',  'monitor_peripheral'),

    # Expansão
    ('hub',          'extensor_usb'),
    ('dock',         'docking_station'),
    ('docking',      'docking_station'),

    # Leitores
    ('card reader',  'hd_externo'),
    ('leitor',       'hd_externo'),
    ('smartcard',    'peripheral'),
    ('smart card',   'peripheral'),
]


# ─── Funções públicas ─────────────────────────────────────────────────────────

def _classify_from_compatible_ids(compatible_ids: list[str]) -> str | None:
    """
    Tenta classificar um dispositivo usando seus CompatibleIDs.
    Suporta tanto HID CompatibleIDs quanto USB class codes.
    Retorna device_type ou None se não reconhecido.
    """
    for cid in compatible_ids:
        cid_upper = cid.upper().strip()
        # 1. HID-specific strings (HID\ devices)
        result = HID_COMPATIBLE_ID_MAP.get(cid_upper)
        if result:
            return result
        # 2. USB class codes (USB\ devices) — usar startswith para cobrir variantes
        for prefix, dtype in USB_CLASS_COMPAT_PREFIXES:
            if cid_upper.startswith(prefix):
                return dtype
    return None


def classify(
    pnp_class_guid: str | None,
    friendly_name: str | None,
    vid: str = '',
    compatible_ids: list[str] | None = None,
) -> str:
    """
    Retorna um device_type compatível com o DeviceType union do TypeScript.

    Fallback: 'peripheral' para dispositivos reconhecidos mas não classificados,
              'unknown' para hubs/raízes USB (filtrados pelo UsbMonitor).
    """
    # 0. Filtrar hubs/raízes USB antecipadamente
    if friendly_name:
        name_lower = friendly_name.lower()
        if any(x in name_lower for x in ['root hub', 'usb hub', 'composite device', 'usb composite']):
            return 'unknown'

    # 1. CompatibleIDs (melhor para HID: mouse, teclado, headset)
    if compatible_ids:
        result = _classify_from_compatible_ids(compatible_ids)
        if result:
            return result

    # 2. Class GUID (para dispositivos com driver de classe dedicado)
    guid_type: str | None = None
    if pnp_class_guid:
        guid_type = PNP_CLASS_MAP.get(pnp_class_guid.upper())

    # Para interfaces de entrada, o driver de classe e mais confiavel que um
    # nome generico ou incorreto fornecido pelo fabricante.
    if guid_type in ('mouse', 'teclado'):
        return guid_type

    # 3. Nome amigável (heurística por substring) — tem prioridade sobre GUID
    # quando o nome contém info mais específica (ex: "Wireless LAN" > "Net")
    if friendly_name:
        name_lower = friendly_name.lower()
        for keyword, device_type in NAME_HEURISTICS:
            if keyword in name_lower:
                return device_type

    if guid_type:
        return guid_type

    # 4. Fallback
    return 'peripheral'


def classify_physical(
    pnp_class_guid: str | None,
    friendly_name: str | None,
    vid: str = '',
    compatible_ids: list[str] | None = None,
    interfaces: list[dict] | None = None,
) -> tuple[str, str]:
    """Classify one physical USB device using its aggregated child interfaces."""
    name_type = classify(None, friendly_name, vid, [])
    if name_type not in ('peripheral', 'unknown'):
        return name_type, 'physical_name'

    interface_types: list[str] = []
    for interface in interfaces or []:
        interface_type = classify(
            interface.get('class_guid'),
            interface.get('friendly_name'),
            vid,
            interface.get('compatible_ids') or [],
        )
        if interface_type not in ('peripheral', 'unknown', 'adaptador_usb'):
            interface_types.append(interface_type)

    # Mouses gamer normalmente publicam interfaces extras de teclado para macros.
    # Um teclado real costuma ser identificado no nome reportado pelo barramento,
    # avaliado acima. Sem esse nome, a presenca de uma interface Mouse e a melhor
    # evidencia fisica disponivel.
    priority = (
        'mouse', 'teclado', 'webcam', 'headset', 'fone', 'impressora',
        'scanner', 'hd_externo', 'pen_drive', 'adaptador_rede_dongle_wifi',
        'adaptador_rede_usb', 'adaptador_bluetooth',
    )
    for device_type in priority:
        if device_type in interface_types:
            return device_type, 'child_interface'

    root_type = classify(pnp_class_guid, friendly_name, vid, compatible_ids)
    if root_type not in ('peripheral', 'unknown'):
        return root_type, 'physical_class'
    return root_type, 'fallback'
