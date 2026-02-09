"""
fex.py - Teste de RTR Multiplataforma com Execução em Batch
Adaptado para usar o método de execução batch do test_upload_cs.py

Uso:
  # executar script em um host específico
  python3 fex.py --device <DEVICE_ID> --script <SCRIPT_PATH>

  # executar script em todos os hosts do tenant
  python3 fex.py --all --script <SCRIPT_PATH> --batch-size 200

  # buscar dispositivo por nome e executar script
  python3 fex.py --search <NOME> --script <SCRIPT_PATH>

  # executar todos os scripts de uma pasta
  python3 fex.py --all --script-dir <PASTA_SCRIPTS> --batch-size 200

  # filtrar por plataforma e executar script
  python3 fex.py --platform <PLATFORM> --script <SCRIPT_PATH>

  # executar comando direto em todos os hosts
  python3 fex.py --all --command "ls -la"

  # executar comando direto em hosts específicos
  python3 fex.py --search <NOME> --command "whoami"

  # executar script passando hostname como parâmetro
  python3 fex.py --all --script <SCRIPT_PATH> --hostname "HOSTNAME_PLACEHOLDER"

  # listar todos os dispositivos
  python3 fex.py --list
"""

import os
import sys
import time
import argparse
import json
import tempfile
import glob
import logging
from datetime import datetime, timedelta
from typing import List, Dict, Optional

from falconpy import OAuth2, Hosts, RealTimeResponse, RealTimeResponseAdmin

# Arquivo de configuração
CONFIG_FILE = "config.json"

# Códigos de cores ANSI
class Colors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    MAGENTA = '\033[95m'
    CYAN = '\033[96m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    END = '\033[0m'

PULSE_INTERVAL = 15
MAX_PULSES = 8

# Configurações de retry
MAX_RETRIES = 3
RETRY_DELAY_BASE = 2  # Segundos para início do backoff exponencial

# Configurações de cache
CACHE_FILE = "devices_cache.json"
CACHE_MAX_AGE_HOURS = 1

# Configurações de timeout - Aumentado para evitar read timeout
RTR_TIMEOUT = 60  # Aumentado de 30 para 60 segundos

# Configurações de log
RTR_LOG_FILE = "rtr.log"
EXECUTION_LOG_FILE = "execution.log"

# Função para carregar credenciais do config.json
def load_credentials():
    """Carrega credenciais do config.json"""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            credentials = config.get('falcon_credentials', {})
            client_id = credentials.get('client_id')
            client_secret = credentials.get('client_secret')
            
            if not client_id or not client_secret:
                print(f"{Colors.RED}ERRO: Credenciais não encontradas em {CONFIG_FILE}{Colors.END}")
                sys.exit(1)
            
            print(f"{Colors.CYAN}Credenciais carregadas de {CONFIG_FILE}: {client_id[:8]}...{Colors.END}")
            return client_id, client_secret
    except FileNotFoundError:
        print(f"{Colors.RED}ERRO: Arquivo de configuração {CONFIG_FILE} não encontrado{Colors.END}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Colors.RED}ERRO ao parsear {CONFIG_FILE}: {e}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED}ERRO ao carregar credenciais: {e}{Colors.END}")
        sys.exit(1)

# Carrega credenciais
CLIENT_ID, CLIENT_SECRET = load_credentials()

# Inicialização dos serviços
hosts = Hosts(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
rtr = RealTimeResponse(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)
rtr_admin = RealTimeResponseAdmin(client_id=CLIENT_ID, client_secret=CLIENT_SECRET)

# Configuração de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler(RTR_LOG_FILE, mode='a', encoding='utf-8'),
        logging.StreamHandler(sys.stdout)
    ]
)
rtr_logger = logging.getLogger('rtr_execution')


def load_config() -> Dict:
    """Carrega configuração do arquivo config.json"""
    try:
        with open(CONFIG_FILE, 'r', encoding='utf-8') as f:
            config = json.load(f)
            print(f"{Colors.CYAN} Configuração carregada de {CONFIG_FILE}{Colors.END}")
            validate_config(config)
            return config
    except FileNotFoundError:
        print(f"{Colors.RED} Arquivo de configuração {CONFIG_FILE} não encontrado{Colors.END}")
        sys.exit(1)
    except json.JSONDecodeError as e:
        print(f"{Colors.RED} Erro ao parsear {CONFIG_FILE}: {e}{Colors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"{Colors.RED} Erro ao carregar configuração: {e}{Colors.END}")
        sys.exit(1)


def validate_config(config: Dict):
    """Valida se todas as configurações necessárias estão presentes no config.json"""
    errors = []
    warnings = []
    
    # Validação de credenciais Falcon
    if 'falcon_credentials' not in config:
        errors.append("Seção 'falcon_credentials' não encontrada")
    else:
        creds = config['falcon_credentials']
        if 'client_id' not in creds or not creds['client_id']:
            errors.append("'client_id' não encontrado ou vazio em falcon_credentials")
        if 'client_secret' not in creds or not creds['client_secret']:
            errors.append("'client_secret' não encontrado ou vazio em falcon_credentials")
    
    # Mostrar erros e avisos
    if errors:
        print(f"\n{Colors.RED}ERROS de configuração:{Colors.END}")
        for error in errors:
            print(f"  {Colors.RED}✗{Colors.END} {error}")
        print(f"\n{Colors.RED}Corrija os erros antes de continuar.{Colors.END}\n")
        sys.exit(1)
    
    if warnings:
        print(f"\n{Colors.YELLOW}AVISOS de configuração:{Colors.END}")
        for warning in warnings:
            print(f"  {Colors.YELLOW}⚠{Colors.END} {warning}")
        print()
    
    print(f"{Colors.GREEN}✓ Configurações validadas com sucesso{Colors.END}\n")


def clean_log_files():
    """Limpa os arquivos de log antes de cada execução"""
    # Remove o arquivo de log se existir
    if os.path.exists(RTR_LOG_FILE):
        os.remove(RTR_LOG_FILE)
    if os.path.exists(EXECUTION_LOG_FILE):
        os.remove(EXECUTION_LOG_FILE)
    
    # Força o handler do logger a recriar o arquivo
    for handler in rtr_logger.handlers[:]:
        rtr_logger.removeHandler(handler)
    
    # Recria o FileHandler com o arquivo limpo
    file_handler = logging.FileHandler(RTR_LOG_FILE, mode='a', encoding='utf-8')
    file_handler.setFormatter(logging.Formatter('%(asctime)s - %(levelname)s - %(message)s'))
    rtr_logger.addHandler(file_handler)
    
    log_rtr_event("Logs limpos - Iniciando nova execução")


def log_rtr_event(message: str, level: str = "INFO"):
    """Registra eventos no rtr.log"""
    log_msg = f"[{level}] {message}"
    rtr_logger.info(log_msg)


def log_rtr_output(device_id: str, hostname: str, command: str, stdout: str, stderr: str, status: str):
    """Registra output de comando/script no rtr.log (texto e uma linha JSON por máquina)."""
    output_msg = f"Device: {hostname} ({device_id[:8]}...)\nCommand: {command}\nSTDOUT: {stdout}\nSTDERR: {stderr}\nStatus: {status}"
    rtr_logger.info(output_msg)
    # Uma linha JSON por máquina para parsing (device_id, hostname, command, stdout, stderr, status)
    output_json = json.dumps({
        "device_id": device_id,
        "hostname": hostname,
        "command": command,
        "stdout": stdout,
        "stderr": stderr,
        "status": status,
    }, ensure_ascii=False)
    rtr_logger.info(f"RTR_OUTPUT_JSON: {output_json}")


def retry_with_backoff(max_retries=MAX_RETRIES, base_delay=RETRY_DELAY_BASE, exceptions=(Exception,)):
    """
    Decorator que implementa retry com backoff exponencial para chamadas à API.
    
    Args:
        max_retries: Número máximo de tentativas
        base_delay: Delay inicial em segundos (backoff exponencial)
        exceptions: Exceções que devem ser tratadas com retry
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            last_exception = None
            for attempt in range(max_retries):
                try:
                    return func(*args, **kwargs)
                except exceptions as e:
                    last_exception = e
                    if attempt < max_retries - 1:
                        # Backoff exponencial: delay = base_delay * 2^attempt
                        delay = base_delay * (2 ** attempt)
                        log_rtr_event(f"Tentativa {attempt + 1}/{max_retries} falhou: {str(e)[:100]}. Retry em {delay}s...", "WARNING")
                        time.sleep(delay)
                    else:
                        log_rtr_event(f"Todas as {max_retries} tentativas falharam", "ERROR")
            # Se chegou aqui, todas as tentativas falharam
            raise last_exception
        return wrapper
    return decorator


def retry_api_call(func, *args, **kwargs):
    """
    Executa uma chamada à API com retry automático.
    
    Args:
        func: Função da API a ser chamada
        *args, **kwargs: Argumentos para a função
    
    Returns:
        Resultado da chamada à API
    
    Raises:
        Exception: Se todas as tentativas falharem
    """
    last_exception = None
    for attempt in range(MAX_RETRIES):
        try:
            return func(*args, **kwargs)
        except Exception as e:
            last_exception = e
            if attempt < MAX_RETRIES - 1:
                # Backoff exponencial: delay = base_delay * 2^attempt
                delay = RETRY_DELAY_BASE * (2 ** attempt)
                error_msg = str(e)[:100] if len(str(e)) > 100 else str(e)
                log_rtr_event(f"Chamada à API falhou (tentativa {attempt + 1}/{MAX_RETRIES}): {error_msg}. Retry em {delay}s...", "WARNING")
                time.sleep(delay)
            else:
                log_rtr_event(f"Todas as {MAX_RETRIES} tentativas falharam", "ERROR")
    
    # Se chegou aqui, todas as tentativas falharam
    raise last_exception


def append_execution_log(entry: Dict):
    """Adiciona entrada ao execution.log"""
    try:
        with open(EXECUTION_LOG_FILE, 'a', encoding='utf-8') as f:
            timestamp = datetime.now().isoformat()
            log_entry = {
                "timestamp": timestamp,
                **entry
            }
            f.write(json.dumps(log_entry, ensure_ascii=False) + "\n")
    except Exception as e:
        print(f"{Colors.RED}Erro ao escrever execution.log: {e}{Colors.END}")


def get_script_files(script_path: str) -> List[str]:
    """Retorna lista de arquivos de script baseado no caminho fornecido"""
    script_files = []
    
    if os.path.isfile(script_path):
        # É um arquivo único
        script_files.append(script_path)
    elif os.path.isdir(script_path):
        # É uma pasta, busca por arquivos de script
        extensions = ['*.sh', '*.ps1', '*.bat', '*.cmd', '*.py']
        for ext in extensions:
            # Busca recursivamente (já inclui a pasta raiz)
            pattern = os.path.join(script_path, '**', ext)
            script_files.extend(glob.glob(pattern, recursive=True))
        
        # Remove duplicatas mantendo a ordem
        seen = set()
        unique_scripts = []
        for script in script_files:
            if script not in seen:
                seen.add(script)
                unique_scripts.append(script)
        script_files = unique_scripts
        
        if not script_files:
            print(f"{Colors.RED}ERROR: Nenhum arquivo de script encontrado em {script_path}{Colors.END}")
            return []
    else:
        print(f"{Colors.RED}ERROR: Caminho inválido: {script_path}{Colors.END}")
        return []
    
    print(f"{Colors.BLUE}Scripts encontrados: {len(script_files)}{Colors.END}")
    for script in script_files:
        print(f"  {Colors.CYAN}- {script}{Colors.END}")
    
    return script_files


def separate_scripts_by_platform(script_files: List[str]) -> dict:
    """Separa scripts por plataforma (.ps1 para Windows, .sh para Unix)"""
    separated = {
        'windows': [],  # .ps1, .bat, .cmd
        'unix': []      # .sh, .py
    }
    
    for script in script_files:
        ext = os.path.splitext(script)[1].lower()
        if ext in ['.ps1', '.bat', '.cmd']:
            separated['windows'].append(script)
        elif ext in ['.sh', '.py']:
            separated['unix'].append(script)
        else:
            # Assume Unix por padrão
            separated['unix'].append(script)
    
    return separated


def group_devices_by_platform(device_ids: List[str]) -> dict:
    """Agrupa dispositivos por plataforma (Windows, Mac, Linux) usando cache"""
    grouped = {
        'windows': [],
        'mac': [],
        'linux': []
    }
    
    print(f"{Colors.BLUE}Agrupando {len(device_ids)} dispositivos por plataforma (usando cache)...{Colors.END}")
    
    # Tenta usar o cache primeiro
    try:
        if is_cache_valid():
            devices = load_devices_from_cache()
            # Cria um mapa device_id -> platform para busca rápida
            device_platform_map = {}
            for device in devices:
                device_platform_map[device.get('id')] = device.get('platform', 'Unknown')
            
            # Agrupa dispositivos baseado no cache
            for device_id in device_ids:
                platform = device_platform_map.get(device_id, 'Unknown')
                platform_lower = platform.lower()
                
                if 'win' in platform_lower:
                    grouped['windows'].append(device_id)
                elif 'mac' in platform_lower:
                    grouped['mac'].append(device_id)
                else:
                    # Assume Linux para outros
                    grouped['linux'].append(device_id)
            
            print(f"{Colors.GREEN}Agrupamento concluído (usando cache):{Colors.END}")
            print(f"  Windows: {len(grouped['windows'])}")
            print(f"  Mac: {len(grouped['mac'])}")
            print(f"  Linux: {len(grouped['linux'])}")
            
            return grouped
        else:
            print(f"{Colors.YELLOW}Cache inválido, buscando plataformas da API...{Colors.END}")
    except Exception as e:
        print(f"{Colors.YELLOW}⚠️  Erro ao usar cache: {e}. Usando API...{Colors.END}")
    
    # Fallback: busca da API (mais lento)
    print(f"{Colors.BLUE}Buscando {len(device_ids)} dispositivos da API...{Colors.END}")
    try:
        # Busca todos de uma vez
        details_resp = hosts.get_device_details(ids=device_ids)
        if details_resp.get("status_code") in (200, 201):
            resources = details_resp.get("body", {}).get("resources", [])
            for device in resources:
                device_id = device.get('device_id')
                platform = device.get('platform_name', 'Unknown')
                platform_lower = platform.lower()
                
                if 'win' in platform_lower:
                    grouped['windows'].append(device_id)
                elif 'mac' in platform_lower:
                    grouped['mac'].append(device_id)
                else:
                    grouped['linux'].append(device_id)
        else:
            print(f"{Colors.RED}Erro ao buscar detalhes da API: {details_resp.get('status_code')}{Colors.END}")
    except Exception as e:
        print(f"{Colors.RED}Erro ao buscar da API: {e}{Colors.END}")
    
    print(f"{Colors.GREEN}Agrupamento concluído:{Colors.END}")
    print(f"  Windows: {len(grouped['windows'])}")
    print(f"  Mac: {len(grouped['mac'])}")
    print(f"  Linux: {len(grouped['linux'])}")
    
    return grouped


def read_script_content(script_path: str) -> str:
    """Lê o conteúdo de um arquivo de script"""
    try:
        with open(script_path, 'r', encoding='utf-8') as f:
            return f.read()
    except Exception as e:
        print(f"{Colors.RED}ERROR: Erro ao ler script {script_path}: {e}{Colors.END}")
        return ""


def execute_script_batch(script_path: str, host_ids: List[str], script_args: str = "", hostname_param: str = "") -> Dict:
    """Executa script em lote usando o método batch do CrowdStrike"""
    print(f"{Colors.BOLD}Executando script: {script_path}{Colors.END}")
    print(f"{Colors.BLUE}Hosts alvo: {len(host_ids)}{Colors.END}")
    log_rtr_event(f"Iniciando execução de script: {script_path} em {len(host_ids)} hosts")
    
    # Lê o conteúdo do script
    script_content = read_script_content(script_path)
    if not script_content:
        log_rtr_event(f"Falha ao ler script: {script_path}", "ERROR")
        return {"status": "error", "message": "Falha ao ler script"}
    
    script_name = os.path.basename(script_path)
    
    # Se hostname_param foi fornecido, adiciona como parâmetro
    if hostname_param:
        # Busca detalhes dos dispositivos para obter hostnames
        device_details = {}
        if host_ids:
            details_resp = hosts.get_device_details(ids=host_ids)
            if details_resp.get("status_code") in (200, 201):
                resources = details_resp.get("body", {}).get("resources", [])
                for device in resources:
                    device_details[device.get('device_id')] = device.get('hostname', 'unknown')
    
    # Inicia sessão batch
    print(f"{Colors.YELLOW}Iniciando sessão batch...{Colors.END}")
    log_rtr_event(f"Iniciando sessão batch para {len(host_ids)} dispositivos")
    session_init = retry_api_call(rtr.batch_init_sessions, host_ids=host_ids)
    
    # Trata o caso onde nenhum dispositivo conseguiu sessão (todos offline)
    if session_init["status_code"] not in (200, 201):
        error_body = session_init.get("body", {})
        errors = error_body.get("errors", [])
        
        # Verifica se o erro é porque nenhum host conseguiu sessão (todos offline)
        if session_init["status_code"] == 404:
            error_msg = errors[0].get("message", "") if errors else ""
            if "no successful hosts initialized" in error_msg.lower():
                log_rtr_event(f"Todos os dispositivos estão offline ou não conseguiram sessão: {error_body}", "WARNING")
                print(f"{Colors.YELLOW}AVISO: Nenhum dispositivo conseguiu estabelecer sessão (todos podem estar offline){Colors.END}")
                print(f"{Colors.YELLOW}O queue_offline não funciona com batch_init_sessions{Colors.END}")
                print(f"{Colors.YELLOW}Para dispositivos offline, o script será enfileirado quando o dispositivo voltar online{Colors.END}")
                
                # Busca informações detalhadas sobre dispositivos sem sessão
                failed_devices_info = []
                try:
                    failed_details = hosts.get_device_details(ids=host_ids)
                    if failed_details.get("status_code") in (200, 201):
                        failed_resources = failed_details.get("body", {}).get("resources", [])
                        for device in failed_resources:
                            failed_devices_info.append({
                                "device_id": device.get('device_id'),
                                "hostname": device.get('hostname', 'unknown'),
                                "platform": device.get('platform_name', 'unknown'),
                                "status": device.get('status', 'unknown'),
                                "agent_load_flags": device.get('agent_load_flags', 'unknown'),
                                "connection_ip": device.get('connection_ip', 'unknown')
                            })
                except Exception as e:
                    log_rtr_event(f"Erro ao buscar detalhes de dispositivos sem sessão: {e}", "ERROR")
                
                # Escreve no execution.log mesmo sem sessão
                execution_entry = {
                    "execution_type": "script_batch",
                    "script_path": script_path,
                    "batch_id": "",
                    "total_devices_requested": len(host_ids),
                    "devices_with_session": [],
                    "devices_without_session": host_ids,
                    "devices_without_session_details": failed_devices_info,
                    "session_count": 0,
                    "failed_session_count": len(host_ids),
                    "error": "Nenhum dispositivo conseguiu estabelecer sessão (todos offline)"
                }
                append_execution_log(execution_entry)
                
                # Retorna um resultado parcial indicando que nenhum dispositivo conseguiu sessão
                return {
                    "status": "partial",
                    "message": "Nenhum dispositivo conseguiu estabelecer sessão (todos offline). O script será enfileirado quando os dispositivos voltarem online.",
                    "batch_id": "",
                    "results": {}
                }
        
        log_rtr_event(f"Falha ao iniciar sessão batch: {session_init}", "ERROR")
        return {"status": "error", "message": f"Falha ao iniciar sessão batch: {session_init}"}
    
    batch_id = session_init["body"]["batch_id"]
    sessions = session_init["body"]["resources"]
    
    # Verifica se há recursos com erros (dispositivos offline que não conseguiram sessão)
    resources_with_errors = {}
    for aid, resource in sessions.items():
        if resource.get("errors"):
            resources_with_errors[aid] = resource
            # Verifica se offline_queued está False mesmo com queue_offline
            if not resource.get("offline_queued", False):
                log_rtr_event(f"Dispositivo {aid} não foi enfileirado offline (offline_queued=False). Erros: {resource.get('errors', [])}", "WARNING")
    
    # Registra quais dispositivos conseguiram sessão no execution.log
    successful_devices = list(sessions.keys())
    failed_devices = [did for did in host_ids if did not in successful_devices]
    
    # Busca informações detalhadas sobre dispositivos sem sessão
    failed_devices_info = []
    if failed_devices:
        try:
            failed_details = hosts.get_device_details(ids=failed_devices)
            if failed_details.get("status_code") in (200, 201):
                failed_resources = failed_details.get("body", {}).get("resources", [])
                for device in failed_resources:
                    failed_devices_info.append({
                        "device_id": device.get('device_id'),
                        "hostname": device.get('hostname', 'unknown'),
                        "platform": device.get('platform_name', 'unknown'),
                        "status": device.get('status', 'unknown'),  # offline, normal, etc
                        "agent_load_flags": device.get('agent_load_flags', 'unknown'),
                        "connection_ip": device.get('connection_ip', 'unknown')
                    })
        except Exception as e:
            log_rtr_event(f"Erro ao buscar detalhes de dispositivos sem sessão: {e}", "ERROR")
    
    log_rtr_event(f"Sessão batch iniciada: {batch_id}")
    log_rtr_event(f"Dispositivos com sessão: {len(successful_devices)}")
    if failed_devices:
        log_rtr_event(f"Dispositivos sem sessão: {len(failed_devices)}", "WARNING")
        for failed_info in failed_devices_info:
            log_rtr_event(f"  - {failed_info.get('hostname', 'unknown')} - Status: {failed_info.get('status', 'unknown')}")
    
    # Escreve no execution.log
    execution_entry = {
        "execution_type": "script_batch",
        "script_path": script_path,
        "batch_id": batch_id,
        "total_devices_requested": len(host_ids),
        "devices_with_session": successful_devices,
        "devices_without_session": failed_devices,
        "devices_without_session_details": failed_devices_info,
        "session_count": len(successful_devices),
        "failed_session_count": len(failed_devices)
    }
    append_execution_log(execution_entry)
    
    print(f"{Colors.GREEN}SUCCESS: Sessão batch iniciada: {batch_id}{Colors.END}")
    print(f"{Colors.CYAN}Sessões ativas: {len(sessions)}{Colors.END}")
    
    # Executa o script usando runscript
    print(f"{Colors.YELLOW}Executando script...{Colors.END}")
    
    # Se hostname_param foi fornecido, executa individualmente para cada host
    cloud_request = None
    if hostname_param and device_details:
        execution_results = {}
        for device_id in host_ids:
            hostname = device_details.get(device_id, 'unknown')
            # Modifica o script para incluir o hostname como parâmetro
            modified_script = script_content.replace(hostname_param, hostname)
            
            # Executa individualmente para este host
            individual_request = rtr_admin.batch_admin_command(
                base_command="runscript",
                batch_id=batch_id,
                persist_all=True,
                queue_offline=True,
                command_string=f"runscript -Raw=```{modified_script}```"
            )
            
            if individual_request["status_code"] == 201:
                results = individual_request["body"]["combined"]["resources"]
                if device_id in results:
                    execution_results[device_id] = {
                        "stdout": results[device_id].get("stdout", ""),
                        "stderr": results[device_id].get("stderr", ""),
                        "errors": results[device_id].get("errors", []),
                        "status": "success" if not results[device_id].get("stderr") and not results[device_id].get("errors") else "warning"
                    }
                else:
                    execution_results[device_id] = {
                        "stdout": "",
                        "stderr": "No result returned",
                        "errors": [],
                        "status": "error"
                    }
            else:
                execution_results[device_id] = {
                    "stdout": "",
                    "stderr": f"Execution failed: {individual_request}",
                    "errors": [],
                    "status": "error"
                }
        # Processa results como se fosse cloud_request
        results = cloud_request["body"]["combined"]["resources"] if cloud_request else {}
        if not execution_results:
            for device_id, result in results.items():
                execution_results[device_id] = {
                    "stdout": result.get("stdout", ""),
                    "stderr": result.get("stderr", ""),
                    "errors": result.get("errors", []),
                    "status": "success" if not result.get("stderr") and not result.get("errors") else "warning"
                }
    else:
        # Execução normal sem parâmetro hostname
        cloud_request = rtr_admin.batch_admin_command(
            base_command="runscript",
            batch_id=batch_id,
            persist_all=True,
            queue_offline=True,
            command_string=f"runscript -Raw=```{script_content}```"
        )
        
        if cloud_request["status_code"] != 201:
            log_rtr_event(f"Falha na execução: {cloud_request}", "ERROR")
            return {"status": "error", "message": f"Falha na execução: {cloud_request}"}
        
        log_rtr_event(f"Script executado com sucesso!")
        print(f"{Colors.GREEN}SUCCESS: Script executado com sucesso!{Colors.END}")
        
        # Processa resultados
        results = cloud_request["body"]["combined"]["resources"]
        execution_results = {}
        
        for device_id, result in results.items():
            execution_results[device_id] = {
                "stdout": result.get("stdout", ""),
                "stderr": result.get("stderr", ""),
                "errors": result.get("errors", []),
                "status": "success" if not result.get("stderr") and not result.get("errors") else "warning"
            }
    
    # Adiciona informações de stdout/stderr no execution.log
    devices_with_output = []
    devices_with_stderr = []
    devices_no_output = []
    
    for device_id, exec_result in execution_results.items():
        if exec_result.get('stdout'):
            devices_with_output.append(device_id)
        if exec_result.get('stderr'):
            devices_with_stderr.append(device_id)
        if not exec_result.get('stdout') and not exec_result.get('stderr'):
            devices_no_output.append(device_id)
    
    # Dispositivos que tiveram sessão mas não retornaram resultado
    devices_without_result = set(successful_devices) - set(execution_results.keys())
    devices_no_output.extend(list(devices_without_result))
    
    execution_result_entry = {
        "execution_type": "script_batch_results",
        "script_path": script_path,
        "batch_id": batch_id,
        "devices_with_stdout": devices_with_output,
        "devices_with_stderr": devices_with_stderr,
        "devices_no_output": devices_no_output,
        "devices_with_stdout_count": len(devices_with_output),
        "devices_with_stderr_count": len(devices_with_stderr),
        "devices_no_output_count": len(devices_no_output),
        "total_devices_with_session": len(successful_devices),
        "total_executed": len(execution_results),
        "execution_success_rate": f"{len(execution_results)}/{len(successful_devices)} ({100*len(execution_results)/len(successful_devices) if successful_devices else 0:.1f}%)"
    }
    append_execution_log(execution_result_entry)
    
    return {
        "status": "success",
        "batch_id": batch_id,
        "results": execution_results
    }


def list_all_device_ids() -> List[str]:
    """Busca TODOS os IDs de dispositivos, incluindo paginação"""
    all_ids = []
    offset = 0
    limit = 5000  # Máximo por página da API
    
    while True:
        print(f"Buscando dispositivos... offset={offset}, limit={limit}")
        
        qresp = hosts.query_devices_by_filter(
            filter="",
            limit=limit,
            offset=offset
        )
        
        if qresp.get("status_code") not in (200, 201):
            raise RuntimeError(f"Falha query devices: {qresp}")
        
        resources = qresp.get("body", {}).get("resources", [])
        if not resources:
            break  # Não há mais dispositivos
            
        all_ids.extend(resources)
        print(f"Encontrados {len(resources)} dispositivos nesta página (total: {len(all_ids)})")
        
        # Se retornou menos que o limite, é a última página
        if len(resources) < limit:
            break
            
        offset += limit
    
    print(f"Total de dispositivos encontrados: {len(all_ids)}")
    return all_ids


def search_device_by_name(device_name: str) -> List[dict]:
    """Busca dispositivos pelo nome do computador"""
    try:
        # Busca por dispositivos que contenham o nome especificado
        filter_query = f"hostname:*'*{device_name}*'"
        qresp = hosts.query_devices_by_filter(filter=filter_query)
        
        if qresp.get("status_code") not in (200, 201):
            print(f"Erro na busca: {qresp}")
            return []
        
        device_ids = qresp.get("body", {}).get("resources", [])
        if not device_ids:
            print(f"Nenhum dispositivo encontrado com nome contendo '{device_name}'")
            return []
        
        # Busca detalhes dos dispositivos encontrados
        details_resp = hosts.get_device_details(ids=device_ids)
        if details_resp.get("status_code") not in (200, 201):
            print(f"Erro ao buscar detalhes: {details_resp}")
            return []
        
        devices = []
        resources = details_resp.get("body", {}).get("resources", [])
        for device in resources:
            devices.append({
                'id': device.get('device_id'),
                'hostname': device.get('hostname', 'N/A'),
                'platform': device.get('platform_name', 'N/A'),
                'status': device.get('status', 'N/A')
            })
        
        return devices
        
    except Exception as e:
        print(f"Erro na busca por nome: {e}")
        return []


def is_cache_valid() -> bool:
    """Verifica se o arquivo de cache existe e não é mais antigo que 1 hora"""
    if not os.path.exists(CACHE_FILE):
        return False
    
    try:
        file_time = datetime.fromtimestamp(os.path.getmtime(CACHE_FILE))
        current_time = datetime.now()
        age = current_time - file_time
        
        return age < timedelta(hours=CACHE_MAX_AGE_HOURS)
    except Exception:
        return False


def load_devices_from_cache() -> List[dict]:
    """Carrega a lista de dispositivos do arquivo de cache"""
    try:
        with open(CACHE_FILE, 'r', encoding='utf-8') as f:
            data = json.load(f)
            return data.get('devices', [])
    except Exception as e:
        print(f"Erro ao carregar cache: {e}")
        return []


def save_devices_to_cache(devices: List[dict]) -> None:
    """Salva a lista de dispositivos no arquivo de cache"""
    try:
        cache_data = {
            'timestamp': datetime.now().isoformat(),
            'devices': devices
        }
        with open(CACHE_FILE, 'w', encoding='utf-8') as f:
            json.dump(cache_data, f, indent=2, ensure_ascii=False)
        print(f"Cache salvo em {CACHE_FILE}")
    except Exception as e:
        print(f"Erro ao salvar cache: {e}")


def fetch_devices_from_api() -> List[dict]:
    """Busca dispositivos diretamente da API com paginação completa"""
    try:
        device_ids = list_all_device_ids()
        if not device_ids:
            return []
        
        print(f"Buscando detalhes de {len(device_ids)} dispositivos...")
        
        # Busca detalhes em lotes para evitar limite de API
        all_devices = []
        batch_size = 100  # Aumentei o batch size para ser mais eficiente
        
        total_batches = (len(device_ids) + batch_size - 1) // batch_size
        
        for i in range(0, len(device_ids), batch_size):
            batch_num = (i // batch_size) + 1
            batch_ids = device_ids[i:i + batch_size]
            
            print(f"Processando lote {batch_num}/{total_batches} ({len(batch_ids)} dispositivos)...")
            
            details_resp = hosts.get_device_details(ids=batch_ids)
            
            if details_resp.get("status_code") in (200, 201):
                resources = details_resp.get("body", {}).get("resources", [])
                for device in resources:
                    all_devices.append({
                        'id': device.get('device_id'),
                        'hostname': device.get('hostname', 'N/A'),
                        'platform': device.get('platform_name', 'N/A'),
                        'status': device.get('status', 'N/A')
                    })
            else:
                print(f"Erro no lote {batch_num}: {details_resp.get('status_code')}")
        
        print(f"Total de dispositivos processados: {len(all_devices)}")
        return all_devices
        
    except Exception as e:
        print(f"Erro ao buscar dispositivos da API: {e}")
        return []


def list_devices_with_names() -> List[dict]:
    """Lista todos os dispositivos com seus nomes e IDs (com cache)"""
    # Verifica se o cache é válido
    if is_cache_valid():
        print("Usando cache local (arquivo tem menos de 1 hora)")
        devices = load_devices_from_cache()
        if devices:
            return devices
        else:
            print("Cache vazio, buscando da API...")
    else:
        if os.path.exists(CACHE_FILE):
            print("Cache expirado, buscando dados atualizados da API...")
        else:
            print("Cache não encontrado, buscando da API...")
    
    # Busca da API e salva no cache
    devices = fetch_devices_from_api()
    if devices:
        save_devices_to_cache(devices)
    else:
        print("Nenhum dispositivo encontrado na API")
    
    return devices


def get_platform_for_device(device_id: str) -> str:
    resp = hosts.get_device_details(ids=[device_id])
    sc = resp.get("status_code")
    if sc not in (200, 201):
        raise RuntimeError(f"Erro get_device_details ({device_id}): {resp}")
    resources = resp.get("body", {}).get("resources", [])
    if not resources:
        raise RuntimeError(f"Device {device_id} não encontrado.")
    details = resources[0]
    return details.get("platform_name", "Unknown")


def find_device_by_exact_name(computer_name: str) -> dict:
    """Busca um dispositivo pelo nome exato do computador"""
    try:
        # Lista todos os dispositivos e busca pelo nome exato
        devices = list_devices_with_names()
        for device in devices:
            if device['hostname'] == computer_name:
                return device
        return None
    except Exception as e:
        print(f"Erro ao buscar dispositivo por nome: {e}")
        return None


def filter_devices_by_platform(platform_name: str) -> List[dict]:
    """Filtra dispositivos por plataforma usando o cache"""
    try:
        devices = list_devices_with_names()
        filtered_devices = []
        
        for device in devices:
            if device.get('platform', '').lower() == platform_name.lower():
                filtered_devices.append(device)
        
        print(f"Encontrados {len(filtered_devices)} dispositivos com plataforma '{platform_name}'")
        return filtered_devices
        
    except Exception as e:
        print(f"Erro ao filtrar dispositivos por plataforma: {e}")
        return []


def execute_command_batch(command: str, host_ids: List[str]) -> Dict:
    """Executa comando direto em lote usando o método batch do CrowdStrike"""
    print(f"{Colors.BOLD}Executando comando: {command}{Colors.END}")
    print(f"{Colors.BLUE}Hosts alvo: {len(host_ids)}{Colors.END}")
    log_rtr_event(f"Iniciando execução de comando: {command} em {len(host_ids)} hosts")
    
    # Inicia sessão batch
    print(f"{Colors.YELLOW}Iniciando sessão batch...{Colors.END}")
    log_rtr_event(f"Iniciando sessão batch para {len(host_ids)} dispositivos")
    session_init = retry_api_call(rtr.batch_init_sessions, host_ids=host_ids)
    
    # Trata o caso onde nenhum dispositivo conseguiu sessão (todos offline)
    if session_init["status_code"] not in (200, 201):
        error_body = session_init.get("body", {})
        errors = error_body.get("errors", [])
        
        # Verifica se o erro é porque nenhum host conseguiu sessão (todos offline)
        if session_init["status_code"] == 404:
            error_msg = errors[0].get("message", "") if errors else ""
            if "no successful hosts initialized" in error_msg.lower():
                log_rtr_event(f"Todos os dispositivos estão offline ou não conseguiram sessão: {error_body}", "WARNING")
                print(f"{Colors.YELLOW}AVISO: Nenhum dispositivo conseguiu estabelecer sessão (todos podem estar offline){Colors.END}")
                print(f"{Colors.YELLOW}Comandos diretos não suportam queue_offline - apenas scripts podem ser enfileirados{Colors.END}")
                
                # Busca informações detalhadas sobre dispositivos sem sessão
                failed_devices_info = []
                try:
                    failed_details = hosts.get_device_details(ids=host_ids)
                    if failed_details.get("status_code") in (200, 201):
                        failed_resources = failed_details.get("body", {}).get("resources", [])
                        for device in failed_resources:
                            failed_devices_info.append({
                                "device_id": device.get('device_id'),
                                "hostname": device.get('hostname', 'unknown'),
                                "platform": device.get('platform_name', 'unknown'),
                                "status": device.get('status', 'unknown'),
                                "agent_load_flags": device.get('agent_load_flags', 'unknown'),
                                "connection_ip": device.get('connection_ip', 'unknown')
                            })
                except Exception as e:
                    log_rtr_event(f"Erro ao buscar detalhes de dispositivos sem sessão: {e}", "ERROR")
                
                # Escreve no execution.log mesmo sem sessão
                execution_entry = {
                    "execution_type": "command_batch",
                    "command": command,
                    "batch_id": "",
                    "total_devices_requested": len(host_ids),
                    "devices_with_session": [],
                    "devices_without_session": host_ids,
                    "devices_without_session_details": failed_devices_info,
                    "session_count": 0,
                    "failed_session_count": len(host_ids),
                    "error": "Nenhum dispositivo conseguiu estabelecer sessão (todos offline)"
                }
                append_execution_log(execution_entry)
                
                # Retorna um resultado parcial indicando que nenhum dispositivo conseguiu sessão
                return {
                    "status": "partial",
                    "message": "Nenhum dispositivo conseguiu estabelecer sessão (todos offline). Comandos diretos não podem ser enfileirados.",
                    "batch_id": "",
                    "results": {}
                }
        
        log_rtr_event(f"Falha ao iniciar sessão batch: {session_init}", "ERROR")
        return {"status": "error", "message": f"Falha ao iniciar sessão batch: {session_init}"}
    
    batch_id = session_init["body"]["batch_id"]
    sessions = session_init["body"]["resources"]
    
    # Verifica se há recursos com erros (dispositivos offline que não conseguiram sessão)
    resources_with_errors = {}
    for aid, resource in sessions.items():
        if resource.get("errors"):
            resources_with_errors[aid] = resource
            log_rtr_event(f"Dispositivo {aid} teve erro ao iniciar sessão. Erros: {resource.get('errors', [])}", "WARNING")
    
    # Registra quais dispositivos conseguiram sessão no execution.log
    successful_devices = list(sessions.keys())
    failed_devices = [did for did in host_ids if did not in successful_devices]
    
    # Busca informações detalhadas sobre dispositivos sem sessão
    failed_devices_info = []
    if failed_devices:
        try:
            failed_details = hosts.get_device_details(ids=failed_devices)
            if failed_details.get("status_code") in (200, 201):
                failed_resources = failed_details.get("body", {}).get("resources", [])
                for device in failed_resources:
                    failed_devices_info.append({
                        "device_id": device.get('device_id'),
                        "hostname": device.get('hostname', 'unknown'),
                        "platform": device.get('platform_name', 'unknown'),
                        "status": device.get('status', 'unknown'),  # offline, normal, etc
                        "agent_load_flags": device.get('agent_load_flags', 'unknown'),
                        "connection_ip": device.get('connection_ip', 'unknown')
                    })
        except Exception as e:
            log_rtr_event(f"Erro ao buscar detalhes de dispositivos sem sessão: {e}", "ERROR")
    
    log_rtr_event(f"Sessão batch iniciada: {batch_id}")
    log_rtr_event(f"Dispositivos com sessão: {len(successful_devices)}")
    if failed_devices:
        log_rtr_event(f"Dispositivos sem sessão: {len(failed_devices)}", "WARNING")
        for failed_info in failed_devices_info:
            log_rtr_event(f"  - {failed_info.get('hostname', 'unknown')} - Status: {failed_info.get('status', 'unknown')}")
    
    # Escreve no execution.log
    execution_entry = {
        "execution_type": "command_batch",
        "command": command,
        "batch_id": batch_id,
        "total_devices_requested": len(host_ids),
        "devices_with_session": successful_devices,
        "devices_without_session": failed_devices,
        "devices_without_session_details": failed_devices_info,
        "session_count": len(successful_devices),
        "failed_session_count": len(failed_devices)
    }
    append_execution_log(execution_entry)
    
    print(f"{Colors.GREEN}SUCCESS: Sessão batch iniciada: {batch_id}{Colors.END}")
    print(f"{Colors.CYAN}Sessões ativas: {len(sessions)}{Colors.END}")
    
    # Executa o comando usando runscript com -Raw
    print(f"{Colors.YELLOW}Executando comando...{Colors.END}")
    log_rtr_event(f"Executando comando via batch admin")
    cloud_request = rtr_admin.batch_admin_command(
        base_command="runscript",
        batch_id=batch_id,
        persist_all=True,
        command_string=f"runscript -Raw=```{command}```"
    )
    
    if cloud_request["status_code"] != 201:
        log_rtr_event(f"Falha na execução: {cloud_request}", "ERROR")
        return {"status": "error", "message": f"Falha na execução: {cloud_request}"}
    
    log_rtr_event(f"Comando executado com sucesso!")
    print(f"{Colors.GREEN}SUCCESS: Comando executado com sucesso!{Colors.END}")
    
    # Processa resultados
    results = cloud_request["body"]["combined"]["resources"]
    execution_results = {}
    
    for device_id, result in results.items():
        execution_results[device_id] = {
            "stdout": result.get("stdout", ""),
            "stderr": result.get("stderr", ""),
            "errors": result.get("errors", []),
            "status": "success" if not result.get("stderr") and not result.get("errors") else "warning"
        }
    
    # Adiciona informações de stdout/stderr no execution.log
    devices_with_output = []
    devices_with_stderr = []
    devices_no_output = []
    
    for device_id, exec_result in execution_results.items():
        if exec_result.get('stdout'):
            devices_with_output.append(device_id)
        if exec_result.get('stderr'):
            devices_with_stderr.append(device_id)
        if not exec_result.get('stdout') and not exec_result.get('stderr'):
            devices_no_output.append(device_id)
    
    # Dispositivos que tiveram sessão mas não retornaram resultado
    devices_without_result = set(successful_devices) - set(execution_results.keys())
    devices_no_output.extend(list(devices_without_result))
    
    execution_result_entry = {
        "execution_type": "command_batch_results",
        "command": command,
        "batch_id": batch_id,
        "devices_with_stdout": devices_with_output,
        "devices_with_stderr": devices_with_stderr,
        "devices_no_output": devices_no_output,
        "devices_with_stdout_count": len(devices_with_output),
        "devices_with_stderr_count": len(devices_with_stderr),
        "devices_no_output_count": len(devices_no_output),
        "total_devices_with_session": len(successful_devices),
        "total_executed": len(execution_results),
        "execution_success_rate": f"{len(execution_results)}/{len(successful_devices)} ({100*len(execution_results)/len(successful_devices) if successful_devices else 0:.1f}%)"
    }
    append_execution_log(execution_result_entry)
    
    return {
        "status": "success",
        "batch_id": batch_id,
        "results": execution_results
    }


def chunk_list(lst, size):
    for i in range(0, len(lst), size):
        yield lst[i:i + size]


def generate_consolidated_report():
    """Gera um relatório consolidado com todos os batch_ids e dispositivos sem resposta"""
    if not os.path.exists(EXECUTION_LOG_FILE):
        log_rtr_event("Nenhum execution.log encontrado para gerar relatório consolidado", "WARNING")
        return
    
    log_rtr_event("Gerando relatório consolidado...")
    
    batch_ids = []
    devices_without_response = []
    devices_without_session = []
    
    # Lê o execution.log e coleta informações
    with open(EXECUTION_LOG_FILE, 'r', encoding='utf-8') as f:
        for line in f:
            if line.strip():
                entry = json.loads(line)
                execution_type = entry.get('execution_type', '')
                
                # Coleta batch_ids
                if execution_type in ['command_batch', 'script_batch']:
                    batch_id = entry.get('batch_id')
                    if batch_id:
                        batch_ids.append(batch_id)
                
                # Coleta devices sem resposta
                if execution_type in ['command_batch_results', 'script_batch_results']:
                    devices_no_output = entry.get('devices_no_output', [])
                    for device_id in devices_no_output:
                        if device_id not in [d['device_id'] for d in devices_without_response]:
                            devices_without_response.append({
                                'device_id': device_id,
                                'reason': 'no_output',
                                'batch_id': entry.get('batch_id', '')
                            })
                
                # Coleta devices sem sessão
                if execution_type in ['command_batch', 'script_batch']:
                    devices_no_session = entry.get('devices_without_session', [])
                    for device_id in devices_no_session:
                        if device_id not in [d['device_id'] for d in devices_without_session]:
                            devices_without_session.append({
                                'device_id': device_id,
                                'reason': 'no_session',
                                'batch_id': entry.get('batch_id', '')
                            })
    
    # Combina todos os dispositivos problemáticos
    all_problematic_devices = []
    
    for device in devices_without_response:
        all_problematic_devices.append(device['device_id'])
    
    for device in devices_without_session:
        if device['device_id'] not in all_problematic_devices:
            all_problematic_devices.append(device['device_id'])
    
    # Busca detalhes dos dispositivos problemáticos
    device_details_list = []
    if all_problematic_devices:
        log_rtr_event(f"Buscando detalhes de {len(all_problematic_devices)} dispositivos problemáticos...")
        
        # Busca em lotes de 100
        batch_size = 100
        for i in range(0, len(all_problematic_devices), batch_size):
            batch_ids_problematic = all_problematic_devices[i:i + batch_size]
            try:
                details_resp = hosts.get_device_details(ids=batch_ids_problematic)
                if details_resp.get("status_code") in (200, 201):
                    resources = details_resp.get("body", {}).get("resources", [])
                    for device_info in resources:
                        device_details_list.append({
                            'device_id': device_info.get('device_id'),
                            'hostname': device_info.get('hostname', 'unknown'),
                            'platform': device_info.get('platform_name', 'unknown')
                        })
            except Exception as e:
                log_rtr_event(f"Erro ao buscar detalhes: {e}", "ERROR")
    
    # Cria relatório consolidado
    consolidated_report = {
        'timestamp': datetime.now().isoformat(),
        'total_batches': len(batch_ids),
        'batch_ids': batch_ids,
        'devices_without_response_count': len(devices_without_response),
        'devices_without_session_count': len(devices_without_session),
        'total_problematic_devices': len(all_problematic_devices),
        'devices_details': device_details_list
    }
    
    # Salva relatório consolidado
    report_file = "consolidated_report.json"
    with open(report_file, 'w', encoding='utf-8') as f:
        json.dump(consolidated_report, f, indent=2, ensure_ascii=False)
    
    log_rtr_event(f"Relatório consolidado gerado: {report_file}")
    print(f"{Colors.GREEN}SUCCESS: Relatório consolidado gerado em {report_file}{Colors.END}")
    print(f"{Colors.CYAN}  - Total de batches: {len(batch_ids)}{Colors.END}")
    print(f"{Colors.CYAN}  - Dispositivos sem resposta: {len(devices_without_response)}{Colors.END}")
    print(f"{Colors.CYAN}  - Dispositivos sem sessão: {len(devices_without_session)}{Colors.END}")
    print(f"{Colors.CYAN}  - Total de dispositivos problemáticos: {len(all_problematic_devices)}{Colors.END}")


def process_command_execution(command: str, device_ids: List[str]):
    """Processa execução de comando direto em lote"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}EXECUÇÃO DE COMANDO EM LOTE{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Comando: {Colors.CYAN}{command}{Colors.END}")
    print(f"{Colors.BOLD}Dispositivos: {Colors.BLUE}{len(device_ids)}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
    
    # Executa o comando
    result = execute_command_batch(command, device_ids)
    
    if result["status"] == "partial":
        print(f"{Colors.YELLOW}AVISO: {result['message']}{Colors.END}")
        print(f"{Colors.YELLOW}Nenhum dispositivo conseguiu estabelecer sessão. Verifique o execution.log para detalhes.{Colors.END}")
        return
    elif result["status"] != "success":
        print(f"{Colors.RED}ERROR: Erro na execução: {result['message']}{Colors.END}")
        return
    
    # Exibe resultados
    print(f"\n{Colors.BOLD}{Colors.GREEN}RESULTADOS DA EXECUÇÃO:{Colors.END}")
    print(f"{Colors.GREEN}{'='*60}{Colors.END}")
    
    # Busca detalhes dos dispositivos para exibir nomes
    device_details = {}
    if device_ids:
        details_resp = hosts.get_device_details(ids=device_ids)
        if details_resp.get("status_code") in (200, 201):
            resources = details_resp.get("body", {}).get("resources", [])
            for device in resources:
                device_details[device.get('device_id')] = {
                    'hostname': device.get('hostname', 'N/A'),
                    'platform': device.get('platform_name', 'N/A')
                }
    
    for device_id, exec_result in result["results"].items():
        device_info = device_details.get(device_id, {'hostname': device_id, 'platform': 'N/A'})
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}{device_info['hostname']} ({device_info['platform']}){Colors.END}")
        print(f"   {Colors.CYAN}ID: {device_id}{Colors.END}")
        status_color = Colors.GREEN if exec_result['status'] == 'success' else Colors.YELLOW
        print(f"   {Colors.BOLD}Status: {status_color}{exec_result['status']}{Colors.END}")
        
        if exec_result['stdout']:
            print(f"   {Colors.GREEN}STDOUT:{Colors.END}")
            print(f"   {Colors.WHITE}{exec_result['stdout']}{Colors.END}")
            try:
                parsed_stdout = json.loads(exec_result['stdout'].strip())
                print(f"   {Colors.CYAN}✓ STDOUT detectado como JSON válido{Colors.END}")
                print(f"   {Colors.CYAN}  Seções: {', '.join(parsed_stdout.keys())}{Colors.END}")
            except (json.JSONDecodeError, ValueError):
                if exec_result['stdout'].strip():
                    print(f"   {Colors.YELLOW}⚠ STDOUT não é JSON válido{Colors.END}")
        
        if exec_result['stderr']:
            print(f"   {Colors.YELLOW}STDERR:{Colors.END}")
            print(f"   {Colors.YELLOW}{exec_result['stderr']}{Colors.END}")
        
        if exec_result['errors']:
            print(f"   {Colors.RED}ERROS:{Colors.END}")
            for error in exec_result['errors']:
                print(f"   {Colors.RED}[{error.get('code', 'N/A')}] {error.get('message', 'N/A')}{Colors.END}")
        
        log_rtr_output(
            device_id=device_id,
            hostname=device_info.get('hostname', 'unknown'),
            command=command,
            stdout=exec_result.get('stdout', ''),
            stderr=exec_result.get('stderr', ''),
            status=exec_result.get('status', 'unknown')
        )
        
        print(f"   {Colors.BLUE}{'-'*50}{Colors.END}")


def process_script_execution(script_path: str, device_ids: List[str], script_args: str = "", hostname_param: str = ""):
    """Processa execução de script em lote"""
    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}EXECUÇÃO DE SCRIPT EM LOTE{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
    print(f"{Colors.BOLD}Script: {Colors.CYAN}{script_path}{Colors.END}")
    print(f"{Colors.BOLD}Dispositivos: {Colors.BLUE}{len(device_ids)}{Colors.END}")
    print(f"{Colors.BOLD}Argumentos: {Colors.YELLOW}{script_args if script_args else 'Nenhum'}{Colors.END}")
    if hostname_param:
        print(f"{Colors.BOLD}Parâmetro Hostname: {Colors.CYAN}{hostname_param}{Colors.END}")
    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
    
    # Executa o script
    result = execute_script_batch(script_path, device_ids, script_args, hostname_param)
    
    if result["status"] == "partial":
        print(f"{Colors.YELLOW}AVISO: {result['message']}{Colors.END}")
        print(f"{Colors.YELLOW}Nenhum dispositivo conseguiu estabelecer sessão. O script será enfileirado quando os dispositivos voltarem online.{Colors.END}")
        print(f"{Colors.YELLOW}Verifique o execution.log para detalhes.{Colors.END}")
        return
    elif result["status"] != "success":
        print(f"{Colors.RED}ERROR: Erro na execução: {result['message']}{Colors.END}")
        return
    
    # Exibe resultados
    print(f"\n{Colors.BOLD}{Colors.GREEN}RESULTADOS DA EXECUÇÃO:{Colors.END}")
    print(f"{Colors.GREEN}{'='*60}{Colors.END}")
    
    # Busca detalhes dos dispositivos para exibir nomes
    device_details = {}
    if device_ids:
        details_resp = hosts.get_device_details(ids=device_ids)
        if details_resp.get("status_code") in (200, 201):
            resources = details_resp.get("body", {}).get("resources", [])
            for device in resources:
                device_details[device.get('device_id')] = {
                    'hostname': device.get('hostname', 'N/A'),
                    'platform': device.get('platform_name', 'N/A')
                }
    
    for device_id, exec_result in result["results"].items():
        device_info = device_details.get(device_id, {'hostname': device_id, 'platform': 'N/A'})
        
        print(f"\n{Colors.BOLD}{Colors.WHITE}{device_info['hostname']} ({device_info['platform']}){Colors.END}")
        print(f"   {Colors.CYAN}ID: {device_id}{Colors.END}")
        status_color = Colors.GREEN if exec_result['status'] == 'success' else Colors.YELLOW
        print(f"   {Colors.BOLD}Status: {status_color}{exec_result['status']}{Colors.END}")
        
        if exec_result['stdout']:
            print(f"   {Colors.GREEN}STDOUT:{Colors.END}")
            print(f"   {Colors.WHITE}{exec_result['stdout']}{Colors.END}")
            try:
                parsed_stdout = json.loads(exec_result['stdout'].strip())
                print(f"   {Colors.CYAN}✓ STDOUT detectado como JSON válido{Colors.END}")
                print(f"   {Colors.CYAN}  Seções: {', '.join(parsed_stdout.keys())}{Colors.END}")
            except (json.JSONDecodeError, ValueError):
                print(f"   {Colors.YELLOW}⚠ STDOUT não é JSON válido{Colors.END}")
        
        if exec_result['stderr']:
            print(f"   {Colors.YELLOW}STDERR:{Colors.END}")
            print(f"   {Colors.YELLOW}{exec_result['stderr']}{Colors.END}")
        
        if exec_result['errors']:
            print(f"   {Colors.RED}ERROS:{Colors.END}")
            for error in exec_result['errors']:
                print(f"   {Colors.RED}[{error.get('code', 'N/A')}] {error.get('message', 'N/A')}{Colors.END}")
        
        log_rtr_output(
            device_id=device_id,
            hostname=device_info.get('hostname', 'unknown'),
            command=f"Script: {os.path.basename(script_path)}",
            stdout=exec_result.get('stdout', ''),
            stderr=exec_result.get('stderr', ''),
            status=exec_result.get('status', 'unknown')
        )
        
        print(f"   {Colors.BLUE}{'-'*50}{Colors.END}")


def main():
    parser = argparse.ArgumentParser(description="Execução de scripts em lote via CrowdStrike RTR")
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--device", help="Device ID para executar")
    group.add_argument("--all", action="store_true", help="Executa para todos os devices")
    group.add_argument("--search", help="Busca dispositivos por nome (hostname)")
    group.add_argument("--list", action="store_true", help="Lista todos os dispositivos com nomes e IDs")
    group.add_argument("--computer-name", help="Nome exato do computador para buscar e executar")
    group.add_argument("--platform", help="Filtrar dispositivos por plataforma (Mac, Windows, Linux, etc)")
    
    parser.add_argument("--script", help="Caminho para o script ou pasta de scripts")
    parser.add_argument("--script-dir", help="Pasta contendo scripts para executar")
    parser.add_argument("--args", help="Argumentos para passar aos scripts", default="")
    parser.add_argument("--hostname", help="Passar hostname como parâmetro para o script")
    parser.add_argument("-c", "--command", help="Executar comando direto em hostnames ou device_ids")
    parser.add_argument("--batch-size", type=int, default=500, help="Qtd de IDs por batch (default=200)")
    
    args = parser.parse_args()
    
    # Limpa logs antes de cada execução (exceto para --list)
    # NOTA: Desativado - no Windows causa PermissionError [WinError 32] ao tentar
    # os.remove(RTR_LOG_FILE) pois o arquivo já está aberto pelo FileHandler do logging.
    # if not args.list:
    #     clean_log_files()
    
    # Validação de argumentos para execução
    if not args.list and not args.search and not args.computer_name and not args.platform:
        if not args.script and not args.script_dir and not args.command:
            print(f"{Colors.RED}ERROR: --script, --script-dir ou --command é obrigatório para execução{Colors.END}")
            sys.exit(1)
    
    # Determina scripts para executar
    scripts_to_execute = []
    if args.script:
        scripts_to_execute = get_script_files(args.script)
    elif args.script_dir:
        scripts_to_execute = get_script_files(args.script_dir)
    
    if not scripts_to_execute and not args.list and not args.search and not args.computer_name and not args.platform and not args.command:
        print(f"{Colors.RED}ERROR: Nenhum script encontrado para executar{Colors.END}")
        sys.exit(1)
    
    # Lista dispositivos
    if args.list:
        print("Listando todos os dispositivos...")
        devices = list_devices_with_names()
        if devices:
            print(f"\nTotal de dispositivos: {len(devices)}")
            for device in devices:
                print(f"ID: {device['id']}")
                print(f"Hostname: {device['hostname']}")
                print(f"Platform: {device['platform']}")
                print(f"Status: {device['status']}")
                print("-" * 50)
        else:
            print("Nenhum dispositivo encontrado.")
        return
    
    # Busca dispositivos (apenas lista se não há comando para executar)
    if args.search and not args.command and not scripts_to_execute:
        print(f"Buscando dispositivos com nome contendo '{args.search}'...")
        devices = search_device_by_name(args.search)
        if devices:
            print(f"\nEncontrados {len(devices)} dispositivo(s):")
            for device in devices:
                print(f"ID: {device['id']}")
                print(f"Hostname: {device['hostname']}")
                print(f"Platform: {device['platform']}")
                print(f"Status: {device['status']}")
                print("-" * 50)
        else:
            print("Nenhum dispositivo encontrado.")
        return
    
    # Busca por nome exato
    if args.computer_name:
        print(f"Buscando dispositivo com nome exato: '{args.computer_name}'...")
        device = find_device_by_exact_name(args.computer_name)
        if device:
            print(f"Dispositivo encontrado:")
            print(f"ID: {device['id']}")
            print(f"Hostname: {device['hostname']}")
            print(f"Platform: {device['platform']}")
            print(f"Status: {device['status']}")
            
            # Executa scripts no dispositivo encontrado
            for script in scripts_to_execute:
                process_script_execution(script, [device['id']], args.args, args.hostname)
            
        else:
            print(f"Dispositivo com nome '{args.computer_name}' não encontrado.")
            print("Use --list para ver todos os dispositivos disponíveis.")
        return
    
    # Filtro por plataforma
    if args.platform:
        print(f"Filtrando dispositivos por plataforma: '{args.platform}'...")
        devices = filter_devices_by_platform(args.platform)
        if not devices:
            print(f"Nenhum dispositivo encontrado com plataforma '{args.platform}'")
            return
        
        device_ids = [device['id'] for device in devices]
        print(f"Total de dispositivos {args.platform}: {len(device_ids)}")
        
        # Mensagem informativa sobre quantas máquinas serão executadas
        if args.command:
            print(f"{Colors.BOLD}{Colors.CYAN}Será executado o comando '{args.command}' em {len(device_ids)} máquinas{Colors.END}")
        elif scripts_to_execute:
            print(f"{Colors.BOLD}{Colors.CYAN}Será executado {len(scripts_to_execute)} script(s) em {len(device_ids)} máquinas{Colors.END}")
            for script in scripts_to_execute:
                print(f"  {Colors.YELLOW}- {script}{Colors.END}")
        
        # Se comando direto foi especificado
        if args.command:
            # Processa em lotes
            for idx, batch in enumerate(chunk_list(device_ids, args.batch_size), start=1):
                print(f"\n>>> Batch {idx} ({len(batch)} devices) <<<")
                process_command_execution(args.command, batch)
        else:
            # Executa scripts
            for idx, batch in enumerate(chunk_list(device_ids, args.batch_size), start=1):
                print(f"\n>>> Batch {idx} ({len(batch)} devices) <<<")
                for script in scripts_to_execute:
                    process_script_execution(script, batch, args.args, args.hostname)
        
        # Gera relatório consolidado
        if os.path.exists(EXECUTION_LOG_FILE):
            generate_consolidated_report()
        
        return
    
    # Execução de comando direto
    if args.command:
        if args.all:
            device_ids = list_all_device_ids()
            print(f"Total de devices: {len(device_ids)}")
            
            # Processa em lotes
            for idx, batch in enumerate(chunk_list(device_ids, args.batch_size), start=1):
                print(f"\n>>> Batch {idx} ({len(batch)} devices) <<<")
                process_command_execution(args.command, batch)
        elif args.device:
            process_command_execution(args.command, [args.device])
        elif args.search:
            print(f"Buscando dispositivos com nome contendo '{args.search}'...")
            devices = search_device_by_name(args.search)
            if devices:
                device_ids = [device['id'] for device in devices]
                process_command_execution(args.command, device_ids)
            else:
                print("Nenhum dispositivo encontrado.")
        
        # Gera relatório consolidado
        if os.path.exists(EXECUTION_LOG_FILE):
            generate_consolidated_report()
        
        return
    
    # Execução em lote
    if args.all:
        device_ids = list_all_device_ids()
        print(f"Total de devices: {len(device_ids)}")
        
        # Se --script-dir foi usado, separa scripts por plataforma e executa inteligentemente
        if args.script_dir and scripts_to_execute:
            print(f"{Colors.BOLD}{Colors.CYAN}MODO INTELIGENTE: Separando scripts por plataforma{Colors.END}")
            
            # Separa scripts por plataforma
            separated_scripts = separate_scripts_by_platform(scripts_to_execute)
            
            print(f"\n{Colors.BLUE}Scripts para Windows (.ps1/.bat/.cmd):{Colors.END}")
            for script in separated_scripts['windows']:
                print(f"  {Colors.CYAN}- {script}{Colors.END}")
            
            print(f"\n{Colors.BLUE}Scripts para Unix (.sh/.py):{Colors.END}")
            for script in separated_scripts['unix']:
                print(f"  {Colors.CYAN}- {script}{Colors.END}")
            
            # Agrupa dispositivos por plataforma
            devices_by_platform = group_devices_by_platform(device_ids)
            
            # Executa scripts Windows (.ps1) apenas em dispositivos Windows
            if separated_scripts['windows'] and devices_by_platform['windows']:
                print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
                print(f"{Colors.BOLD}EXECUTANDO SCRIPTS WINDOWS (.ps1) EM {len(devices_by_platform['windows'])} DISPOSITIVOS{Colors.END}")
                print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
                
                # Processa em lotes
                for idx, batch in enumerate(chunk_list(devices_by_platform['windows'], args.batch_size), start=1):
                    print(f"\n>>> Batch Windows {idx} ({len(batch)} devices) <<<")
                    for script in separated_scripts['windows']:
                        process_script_execution(script, batch, args.args, args.hostname)
            
            # Executa scripts Unix (.sh) apenas em dispositivos Mac/Linux
            if separated_scripts['unix'] and (devices_by_platform['mac'] or devices_by_platform['linux']):
                unix_devices = devices_by_platform['mac'] + devices_by_platform['linux']
                if unix_devices:
                    print(f"\n{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
                    print(f"{Colors.BOLD}EXECUTANDO SCRIPTS UNIX (.sh) EM {len(unix_devices)} DISPOSITIVOS{Colors.END}")
                    print(f"{Colors.BOLD}{Colors.MAGENTA}{'='*60}{Colors.END}")
                    
                    # Processa em lotes
                    for idx, batch in enumerate(chunk_list(unix_devices, args.batch_size), start=1):
                        print(f"\n>>> Batch Unix {idx} ({len(batch)} devices) <<<")
                        for script in separated_scripts['unix']:
                            process_script_execution(script, batch, args.args, args.hostname)
        else:
            # Comportamento tradicional: executa todos os scripts em todos os dispositivos
            # Processa em lotes
            for idx, batch in enumerate(chunk_list(device_ids, args.batch_size), start=1):
                print(f"\n>>> Batch {idx} ({len(batch)} devices) <<<")
                
                # Executa cada script no lote
                for script in scripts_to_execute:
                    process_script_execution(script, batch, args.args, args.hostname)
    
    # Execução em dispositivo específico
    elif args.device:
        for script in scripts_to_execute:
            process_script_execution(script, [args.device], args.args, args.hostname)
    
    # Execução com busca por nome
    elif args.search:
        print(f"Buscando dispositivos com nome contendo '{args.search}'...")
        devices = search_device_by_name(args.search)
        if devices:
            device_ids = [device['id'] for device in devices]
            print(f"Total de dispositivos encontrados: {len(device_ids)}")
            for script in scripts_to_execute:
                process_script_execution(script, device_ids, args.args, args.hostname)
        else:
            print("Nenhum dispositivo encontrado.")
    
    # Gera relatório consolidado ao final (se ainda não foi gerado)
    if os.path.exists(EXECUTION_LOG_FILE):
        generate_consolidated_report()


if __name__ == "__main__":
    main()
