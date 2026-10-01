# Comandos remotos

O agente `1.3.26` pode buscar um comando pendente no servidor e executá-lo
como o usuário do serviço do Windows. A execução é não interativa: stdin fica
desconectado e o agente aceita apenas `powershell` ou `cmd`.

Fluxo do agente:

1. A cada 15 segundos, faz `POST /api/agent/commands/claim` com
   `{"agent_version":"1.3.26"}`.
2. Persiste `command_id`, `receipt_token` e o estado `started` no journal
   SQLite local antes de iniciar o processo.
3. Executa um único comando por vez, com timeout entre 10 e 300 segundos.
4. Persiste o resultado no journal antes de fazer
   `POST /api/agent/commands/:id/result`.
5. Só busca outro comando depois que o resultado pendente for confirmado.

O journal fica ao lado do banco local, no arquivo `agent.commands.sqlite3`.
Se o serviço reiniciar com uma execução em `started`/`running`, ela é marcada
como `unknown` e o comando não é executado novamente. Falhas de rede repetem
somente o envio do resultado.

## Segurança e limites

- O canal de comandos exige HTTPS e usa o token do agente no header
  `X-Agent-Token`.
- O servidor de comandos aceito pelo agente é exclusivamente
  `https://inventario.in9automacao.com.br`; URLs alternativas e redirects são
  rejeitados.
- O consumo remoto só é habilitado no processo do serviço executado como
  LocalSystem, depois do enrollment `secure_data_acl_v1`. O modo standalone e
  o tray não abrem o canal de comandos.
- O diretório de dados e todos os seus descendentes são validados antes de
  qualquer chamada de rede. Em Windows, a ACL protegida contém somente
  LocalSystem e Administrators com controle total; reparse points fazem o
  serviço falhar fechado.
- PowerShell usa o executável absoluto do Windows PowerShell com
  `-NoLogo -NoProfile -NonInteractive -EncodedCommand` em UTF-16LE.
- CMD usa o executável absoluto com `/d /s /c`, sem `shell=True`.
- Timeout e parada encerram a árvore do processo por Job Object no Windows,
  com `KILL_ON_JOB_CLOSE`.
- stdout e stderr são drenados continuamente e limitados a 64 KiB combinados.
  O resultado informa `output_truncated` quando houver corte.
- O comando tem limite de 16 KiB em UTF-8; CMD também respeita o limite de
  8.191 caracteres da linha de comando do Windows.

O recurso deve ser exposto pelo painel somente a administradores. O agente não
registra o comando nem sua saída nos logs; esses dados ficam apenas no journal
e no resultado autenticado enviado ao servidor.

Antes de habilitar em produção, restrinja o acesso ao journal à conta do serviço
e aos administradores e defina a retenção dos resultados. Comandos podem gerar
efeitos irreversíveis; timeout não desfaz alterações já realizadas.

Validação Windows local (sem servidor):

```text
python -m pytest tests/test_commands_windows.py -q
```
