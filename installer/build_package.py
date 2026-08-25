"""
Monta o payload .zip de um pacote para o canal de instalacao remota do agente.

Rode na maquina de referencia, com o software ja instalado e CONFIGURADO —
o zip carrega a configuracao junto, e o agente so reescreve as chaves que o
manifesto mandar.

Uso:
    python installer/build_package.py "%USERPROFILE%\\Sankhya web" sankhya-web-connection

O sha256 impresso no fim e informativo: o servidor recalcula o hash do arquivo
real ao publicar o manifesto, entao nao precisa colar em lugar nenhum.
"""

import argparse
import hashlib
import os
import sys
import zipfile
from pathlib import Path

# Diretorios que nunca devem viajar da maquina de referencia para o parque
DEFAULT_SKIP_DIRS = {'log', 'logs', 'temp', 'tmp'}

# Usado nas entradas de diretorio sinteticas para o build ser reproduzivel
FIXED_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def build(source: Path, name: str, out_dir: Path, skip_dirs: set[str]) -> Path:
    if not source.is_dir():
        raise SystemExit(f'Pasta de origem nao encontrada: {source}')

    out_dir.mkdir(parents=True, exist_ok=True)
    out_path = out_dir / f'{name}.zip'
    if out_path.exists():
        out_path.unlink()

    files = 0
    raw_bytes = 0
    skipped: list[str] = []

    with zipfile.ZipFile(out_path, 'w', zipfile.ZIP_DEFLATED, compresslevel=6) as archive:
        for root, dirs, filenames in os.walk(source):
            pruned = [d for d in dirs if d.lower() in skip_dirs]
            for d in pruned:
                skipped.append(str(Path(root, d).relative_to(source)))
            dirs[:] = [d for d in dirs if d.lower() not in skip_dirs]

            for filename in filenames:
                full = Path(root) / filename
                # A pasta de origem vira a raiz do zip, entao extract_to aponta
                # para o diretorio PAI (ex.: %USERPROFILE%)
                arcname = Path(source.name) / full.relative_to(source)
                archive.write(full, arcname=str(arcname))
                files += 1
                raw_bytes += full.stat().st_size

        # Recria vazias as pastas podadas: o app pode esperar que existam.
        # date_time fixo porque writestr usaria a hora atual, e isso sozinho
        # faria dois builds do mesmo conteudo terem sha256 diferentes.
        for relative in skipped:
            entry = zipfile.ZipInfo(f'{source.name}/{relative}/'.replace(os.sep, '/'), FIXED_TIMESTAMP)
            entry.external_attr = 0o40755 << 16 | 0x10  # diretorio
            archive.writestr(entry, '')

    size = out_path.stat().st_size
    digest = hashlib.sha256(out_path.read_bytes()).hexdigest()

    print(f'arquivos:  {files}')
    print(f'origem:    {raw_bytes / 1024 / 1024:.1f} MB')
    print(f'podado:    {", ".join(skipped) if skipped else "(nada)"}')
    print(f'zip:       {size / 1024 / 1024:.1f} MB  ({out_path})')
    print(f'sha256:    {digest}')
    return out_path


def main() -> None:
    parser = argparse.ArgumentParser(description='Empacota software para o canal de pacotes do agente')
    parser.add_argument('source', help='Pasta a empacotar (ex.: "%%USERPROFILE%%\\Sankhya web")')
    parser.add_argument('name', help='Nome do pacote (vira <name>.zip e a chave no manifesto)')
    parser.add_argument('--out-dir', default=None, help='Destino do zip (padrao: dist-packages/)')
    parser.add_argument('--keep-logs', action='store_true', help='Nao podar as pastas de log')
    args = parser.parse_args()

    out_dir = Path(args.out_dir) if args.out_dir else Path(__file__).resolve().parent.parent / 'dist-packages'
    skip = set() if args.keep_logs else DEFAULT_SKIP_DIRS
    build(Path(os.path.expandvars(args.source)).resolve(), args.name, out_dir, skip)


if __name__ == '__main__':
    sys.exit(main())
