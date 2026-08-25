# Instalação remota de software (canal de pacotes)

A partir da **v1.3.21** o agente instala software nas máquinas do parque sem
ninguém precisar ir até elas. O servidor publica um manifesto, o agente aplica.

Como o agente roda como **LocalSystem**, ele consegue o que o usuário logado não
consegue: escrever em todos os perfis de `C:\Users`, criar regras de firewall e
gravar em `HKLM`.

## Fluxo

```
agente (a cada 1h)
   │
   ├─ GET /api/agent/packages          → manifesto JSON
   │
   └─ para cada pacote:
        1. detect_path existe?          → se sim, pula a instalação
        2. baixa payload_url            → valida sha256 (obrigatório)
        3. extrai em extract_to         → com proteção contra zip slip
        4. reescreve config_files       → só as chaves listadas
        5. garante as regras de firewall
        6. garante o autostart em HKLM\...\Run
```

Tudo é idempotente. Rodar de novo numa máquina pronta não faz nada.

Para aplicar na hora, sem esperar o ciclo de 1h (útil em máquina piloto):

```
usb_agent.exe install-packages
```

## O que o backend precisa expor

### `GET /api/agent/packages`

Auth: `X-Agent-Token`, mesma regra do heartbeat (máquina aprovada). Agentes
`pending` devem receber `403` — não queremos instalar software em máquina que
ainda não foi aprovada no portal.

Resposta (o agente aceita `[...]`, `{packages:[...]}` ou `{data:{packages:[...]}}`):

```json
{ "success": true, "data": { "packages": [ /* manifestos */ ] } }
```

Se a rota não existir, o agente trata o 404 como "nenhum pacote" e segue a vida.
Isso mantém compatibilidade com o servidor atual.

### `GET /api/agent/packages/:name/download`

Serve o `.zip`. Mesma auth. Aceita `Range` de preferência — são 120 MB por
máquina e retomar download interrompido evita retrabalho.

### Rollout controlado

Recomendo o endpoint filtrar por máquina/grupo, para liberar em 2–3 PCs antes de
soltar geral. Sem isso, um manifesto errado vai para o parque inteiro de uma vez.

## Formato do manifesto

| Campo | Descrição |
|---|---|
| `name` | Identificador do pacote |
| `scope` | `per-user` (instala em cada perfil) ou ausente (machine-wide) |
| `payload_url` | URL do `.zip` (relativa ao servidor ou absoluta) |
| `sha256` | **Obrigatório.** Sem ele o agente recusa o payload |
| `extract_to` | Destino da extração. `%USERPROFILE%` é resolvido por perfil |
| `detect_path` | Se existir, o pacote é considerado instalado |
| `config_files[]` | `path`, `format` (`jvm_args`\|`properties`), `values` |
| `firewall[]` | `name`, `ports`, `protocol`, `direction`, `profiles`, `purge_blocking_rules_matching` |
| `autostart` | `name` e `command` gravados em `HKLM\...\Run` como `REG_EXPAND_SZ` |

### Sobre `config_files`

O agente reescreve **apenas as chaves listadas em `values`**, preservando o resto
do arquivo. Isso não é preciosismo: o `web_connection.l4j.ini` mistura
configuração de servidor (`skwHost`, `porta`) com configuração de hardware local
(`balancaPort=COM9`). Sobrescrever o arquivo inteiro quebraria toda máquina que
tem balança ligada numa porta COM diferente.

Antes da primeira alteração o agente salva um `.in9bak` ao lado do arquivo.

### Sobre `firewall`

**Use `program`.** Uma regra só de porta não impede o diálogo *"Permitir que
este aplicativo se comunique na rede"*: o Windows dispara esse prompt com base no
**programa** que abre o socket, e confirmá-lo exige senha de administrador — o
que trava o usuário comum logo no logon. A regra precisa apontar para o binário.

Cuidado com qual binário: no Sankhya WC quem escuta não é o `web_connection.exe`,
que é apenas um launcher, e sim o `javaw.exe` da JRE embutida. Descubra o certo
com `netstat -ano | findstr <porta>` e o PID no Gerenciador de Tarefas.

Como o binário mora dentro do perfil do usuário e o Firewall do Windows não
aceita curinga em caminho, o agente cria **uma regra por perfil**, com o nome do
perfil sufixado (`Sankhya Web Connection - fulano`).

Duas formas de limpar bloqueios pré-existentes, que vencem qualquer permissão:

- `purge_blocking_rules_matching` — casa pelo **nome** da regra.
- `purge_blocking_program_matching` — casa pelo **caminho do programa**. Mais
  preciso, e o recomendado: remove só o que aponta para a pasta do app, sem
  arriscar apagar bloqueios legítimos de outros programas Java.

`profiles` default é `Domain,Private`. Evite `Public`.

### Sobre `ensure_running`

O `autostart` só cobre o logon. Se o usuário fechar o app, ou ele cair, fica
fora até o próximo logon. `ensure_running` faz o agente conferir a cada 2
minutos e subir de volta:

```json
"ensure_running": {
  "process_path": "%USERPROFILE%\\...\\jre\\bin\\javaw.exe",
  "command": "\"%USERPROFILE%\\...\\executar\\web_connection.exe\"",
  "cwd": "%USERPROFILE%\\...\\executar"
}
```

`process_path` é **quem realmente fica em memória**, que nem sempre é o que você
dispara — no Sankhya WC se lança `web_connection.exe` mas quem permanece é o
`javaw.exe`. Errar isso faz o agente relançar o app em loop.

O agente roda como LocalSystem, na sessão 0. Ele **não** pode dar um start
qualquer num app de GUI: o processo nasceria invisível e, pior, com o contexto
de impressoras do SYSTEM em vez do usuário — o que quebraria justamente a função
do Web Connection. Por isso o lançamento passa por `CreateProcessAsUser` com o
token da sessão interativa (`agent/win_session.py`). Sessões simultâneas (troca
rápida de usuário, RDP) são tratadas uma a uma.

Proteções: carência de 90s depois de disparar, para não contar duas vezes
enquanto o app sobe; e após 3 falhas seguidas o agente desiste por 30 minutos e
reporta `package_launch_failed`, em vez de ficar num loop de reinício.

**Consequência esperada:** se o usuário fechar o Web Connection de propósito, ele
volta em até 2 minutos. É o comportamento pedido, mas vale avisar o pessoal.

### Sobre `autostart`

Uma única entrada `REG_EXPAND_SZ` em `HKLM\...\Run` cobre todos os perfis: o
Windows expande `%USERPROFILE%` no logon de cada usuário. Evita ter que montar a
`NTUSER.DAT` de quem está deslogado.

## Manifesto do Sankhya Web Connection

Valores extraídos de uma máquina já configurada
(`web_connection.l4j.ini` + `conf/snklocalapp.conf`):

```json
{
  "name": "sankhya-web-connection",
  "scope": "per-user",
  "payload_url": "/api/agent/packages/sankhya-web-connection/download",
  "sha256": "<preencher com o hash do zip>",
  "extract_to": "%USERPROFILE%",
  "detect_path": "%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\executar\\web_connection.exe",
  "config_files": [
    {
      "path": "%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\executar\\web_connection.l4j.ini",
      "format": "jvm_args",
      "values": {
        "skwHost": "https://fioforte.sankhyacloud.com.br/mge",
        "porta": "9096",
        "portaWebSocket": "9098"
      }
    },
    {
      "path": "%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\executar\\conf\\snklocalapp.conf",
      "format": "properties",
      "values": { "porta": "9096" }
    }
  ],
  "firewall": [
    {
      "name": "Sankhya Web Connection (TCP 9096/9098)",
      "ports": [9096, 9098],
      "protocol": "TCP",
      "direction": "in",
      "profiles": ["Domain", "Private"],
      "program": "%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\jre\\bin\\javaw.exe",
      "purge_blocking_program_matching": "Sankhya web"
    }
  ],
  "autostart": {
    "name": "SankhyaWebConnection",
    "command": "\"%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\executar\\web_connection.exe\""
  },
  "ensure_running": {
    "process_path": "%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\jre\\bin\\javaw.exe",
    "command": "\"%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\executar\\web_connection.exe\"",
    "cwd": "%USERPROFILE%\\Sankhya web\\Sankhya_web_connectionx64\\executar"
  }
}
```

### Notas do Sankhya

- **`skwHost` termina em `/mge`.** A raiz do domínio sozinha não funciona.
- **São duas portas**: `9096` (HTTP) e `9098` (WebSocket). O `porta` precisa bater
  com o parâmetro `PORTAPPPRINT` em *Preferências* no Sankhya.
- **O `.zip` tem ~120 MB** (274 MB extraídos, 188 MB só do JRE embutido). Vale
  liberar fora do horário comercial nas unidades com link fraco.
- **O certificado é estático**, embutido no `snklocalapp.jar` (`sslFile=sankhya.jks`,
  que não existe em disco). Clonar entre máquinas é seguro.
- **A config só vale no próximo logon** do usuário. O agente não reinicia o WC
  se ele já estiver rodando.
- **Quem escuta nas portas é o `jre\bin\javaw.exe`**, não o `web_connection.exe`.
  A regra de firewall tem que apontar para ele, ou o usuário toma o prompt de
  "Permitir acesso" no logon — que pede senha de admin e ele não tem.

## Empacotando

Na máquina de referência, com o WC instalado e configurado:

```
python installer/build_package.py "%USERPROFILE%\Sankhya web" sankhya-web-connection
```

O script poda as pastas de log (são da máquina de referência, não do parque) e o
build é reproduzível — rodar duas vezes gera o mesmo `sha256`.

Você **não precisa colar o hash no manifesto**: o servidor calcula o `sha256` do
arquivo real ao publicar. O campo `sha256` na entrada só existe para forçar um
valor específico, o que raramente é necessário.

Subindo o pacote para o servidor:

```
scp dist-packages/sankhya-web-connection.zip root@<vps>:/root/inventario-ti/server/uploads/packages/
```

ou via `POST /api/agent/upload-package` (campo `package`, com `name` no body,
autenticado como admin).
