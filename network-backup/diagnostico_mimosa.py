#!/usr/bin/env python3
"""
Script de diagnóstico para backup de equipamentos Mimosa C5c/B5c

Uso:
    python diagnostico_mimosa.py <IP> <USUARIO> <SENHA> [PORTA] [PROTOCOLO]

Exemplo:
    python diagnostico_mimosa.py 192.168.1.20 configure minhasenha
    python diagnostico_mimosa.py 192.168.1.20 configure minhasenha 443 https
"""

import sys
import requests
import urllib3

# Desabilitar avisos de SSL
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


def testar_mimosa(ip, username, password, port=443, protocol='https'):
    """Testa conexão e endpoints do Mimosa"""

    base_url = f"{protocol}://{ip}:{port}"
    session = requests.Session()

    print(f"\n{'='*60}")
    print(f"DIAGNÓSTICO MIMOSA - {ip}:{port}")
    print(f"{'='*60}\n")

    # 1. Testar conectividade básica
    print("[1] Testando conectividade básica...")
    try:
        response = session.get(base_url, verify=False, timeout=10)
        print(f"    ✓ Conectou: HTTP {response.status_code}")
        print(f"    Headers: {dict(response.headers)}")
    except Exception as e:
        print(f"    ✗ Erro: {e}")
        print("\n    SOLUÇÃO: Verifique se o IP está correto e se o equipamento está acessível")
        return

    # 2. Testar endpoints de login
    print("\n[2] Testando endpoints de login...")
    login_endpoints = [
        # Mimosa C5c - endpoint principal
        ('/login.php', 'POST', {'username': username, 'password': password}),
        ('/login.php', 'POST', {'password': password}),
        # Outros endpoints
        ('/api/login', 'POST', {'username': username, 'password': password}),
        ('/login', 'POST', {'username': username, 'password': password}),
        ('/login', 'POST', {'password': password}),  # Alguns usam só senha
        ('/?q=index.login', 'POST', {'username': username, 'password': password}),
    ]

    # Headers para simular navegador
    session.headers.update({
        'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36',
        'Accept': 'application/json, text/plain, */*',
        'Accept-Language': 'en-US,en;q=0.9',
        'Origin': base_url,
        'Referer': f'{base_url}/',
    })

    logged_in = False
    for endpoint, method, data in login_endpoints:
        try:
            url = f"{base_url}{endpoint}"
            if method == 'POST':
                response = session.post(url, data=data, verify=False, timeout=10)
            else:
                response = session.get(url, verify=False, timeout=10)

            status = "✓" if response.status_code in [200, 302] else "✗"
            cookies = "Com cookies" if session.cookies else "Sem cookies"
            content_type = response.headers.get('Content-Type', '')
            print(f"    {status} {endpoint}: HTTP {response.status_code} ({cookies}, {content_type})")

            # Verificar sucesso do login
            if response.status_code in [200, 302]:
                # Verificar se é JSON com dados de sessão
                if 'application/json' in content_type:
                    try:
                        json_data = response.json()
                        if 'role' in json_data or 'version' in json_data or 'success' in json_data:
                            logged_in = True
                            print(f"       → Login bem-sucedido! (JSON: {list(json_data.keys())})")
                            break
                    except:
                        pass
                # Verificar se tem cookies de sessão
                if session.cookies:
                    logged_in = True
                    print(f"       → Login bem-sucedido! (Cookies: {list(session.cookies.keys())})")
                    break

        except Exception as e:
            print(f"    ✗ {endpoint}: {e}")

    # 3. Testar endpoints de backup/configuração
    print("\n[3] Testando endpoints de backup...")

    # Se não fez login, usa Basic Auth
    auth = (username, password) if not logged_in else None

    config_endpoints = [
        # Endpoint principal descoberto
        '/?q=preferences.configure&mimosa_action=download',

        # Outros endpoints
        '/?q=backup.download',
        '/backup/download',
        '/config/backup',
        '/api/backup',
        '/core/api/config/backup',
        '/core/api/calls/Backup.php',
        '/core/api/service/backup',
        '/cgi-bin/backup.cgi',
        '/backup.cgi',
        '/download/mimosa.conf',
        '/config/download',
        '/api/v1/config',
        '/api/config/export',
        '/config',
        '/',
    ]

    found_config = False
    for endpoint in config_endpoints:
        try:
            url = f"{base_url}{endpoint}"
            response = session.get(url, auth=auth, verify=False, timeout=10)

            content_len = len(response.content)
            content_type = response.headers.get('Content-Type', 'N/A')

            # Verificar se parece ser configuração
            is_config = False
            if content_len > 100:
                text = response.text.lower() if response.text else ''
                keywords = ['mimosa', 'wireless', 'network', 'ssid', 'frequency', 'channel', 'ip', 'config']
                is_config = any(kw in text for kw in keywords)

            status = "✓" if response.status_code == 200 and content_len > 100 else "✗"
            config_flag = " [CONFIG!]" if is_config else ""

            print(f"    {status} {endpoint}: HTTP {response.status_code}, {content_len} bytes, {content_type}{config_flag}")

            if is_config and not found_config:
                found_config = True
                print(f"\n       → ENCONTRADO! Primeiros 200 caracteres:")
                print(f"       {response.text[:200]}...")

        except Exception as e:
            print(f"    ✗ {endpoint}: {e}")

    # 4. Testar API REST com credenciais na URL
    print("\n[4] Testando API REST com credenciais na URL...")
    api_endpoints = [
        f"/core/api/service/backup?username={username}&password={password}",
        f"/core/api/service/config?username={username}&password={password}",
        f"/core/api/service/device-info?username={username}&password={password}",
    ]

    for endpoint in api_endpoints:
        try:
            url = f"{base_url}{endpoint}"
            response = session.get(url, verify=False, timeout=10)
            content_len = len(response.content)

            status = "✓" if response.status_code == 200 and content_len > 100 else "✗"
            print(f"    {status} {endpoint.split('?')[0]}: HTTP {response.status_code}, {content_len} bytes")

            if response.status_code == 200 and content_len > 50:
                print(f"       → Resposta: {response.text[:200]}...")

        except Exception as e:
            print(f"    ✗ {endpoint.split('?')[0]}: {e}")

    # 5. Resumo
    print(f"\n{'='*60}")
    print("RESUMO")
    print(f"{'='*60}")

    if found_config:
        print("✓ Configuração encontrada! O backup deve funcionar.")
    else:
        print("✗ Configuração NÃO encontrada.")
        print("\nPossíveis soluções:")
        print("1. Verifique se HTTPS está habilitado no dispositivo Mimosa")
        print("2. Verifique as credenciais (usuário/senha)")
        print("3. Verifique a versão do firmware do equipamento")
        print("4. Tente acessar manualmente via navegador e veja qual URL faz o download")
        print("\nPara descobrir o endpoint correto:")
        print("1. Abra o navegador e acesse a interface web do Mimosa")
        print("2. Vá em Preferences > Backup & Restore")
        print("3. Clique em 'Backup Current Configuration'")
        print("4. Pressione F12 e veja na aba Network qual URL foi chamada")

    session.close()


if __name__ == '__main__':
    if len(sys.argv) < 4:
        print(__doc__)
        sys.exit(1)

    ip = sys.argv[1]
    username = sys.argv[2]
    password = sys.argv[3]
    port = int(sys.argv[4]) if len(sys.argv) > 4 else 443
    protocol = sys.argv[5] if len(sys.argv) > 5 else 'https'

    testar_mimosa(ip, username, password, port, protocol)
