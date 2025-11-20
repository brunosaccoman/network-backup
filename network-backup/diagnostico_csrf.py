#!/usr/bin/env python3
"""
Diagnóstico de problema CSRF - Network Backup System
Execute este script no servidor de produção para coletar informações de diagnóstico.

Uso: python diagnostico_csrf.py
"""

import os
import sys
import socket
import platform
from datetime import datetime

def print_section(title):
    """Imprime cabeçalho de seção."""
    print("\n" + "=" * 60)
    print(f" {title}")
    print("=" * 60)

def print_item(label, value, status=None):
    """Imprime item com formatação."""
    if status == "ok":
        icon = "✓"
    elif status == "warn":
        icon = "⚠"
    elif status == "error":
        icon = "✗"
    else:
        icon = "•"
    print(f"  {icon} {label}: {value}")

def main():
    print("\n" + "#" * 60)
    print("#  DIAGNÓSTICO DE CSRF - Network Backup System")
    print("#  " + datetime.now().strftime("%Y-%m-%d %H:%M:%S"))
    print("#" * 60)

    # =========================================================================
    # 1. INFORMAÇÕES DO SISTEMA
    # =========================================================================
    print_section("1. INFORMAÇÕES DO SISTEMA")
    print_item("Sistema Operacional", platform.system() + " " + platform.release())
    print_item("Python", sys.version.split()[0])
    print_item("Hostname", socket.gethostname())
    print_item("Diretório atual", os.getcwd())

    # =========================================================================
    # 2. VARIÁVEIS DE AMBIENTE CRÍTICAS
    # =========================================================================
    print_section("2. VARIÁVEIS DE AMBIENTE")

    env_vars = {
        'FLASK_ENV': ('development', 'Define o ambiente'),
        'SECRET_KEY': (None, 'Chave de sessão'),
        'ENCRYPTION_KEY': (None, 'Chave de criptografia'),
        'DATABASE_URL': (None, 'URL do banco'),
        'SESSION_COOKIE_SECURE': ('False', 'Cookie só HTTPS'),
        'WTF_CSRF_ENABLED': ('True', 'CSRF habilitado'),
        'WTF_CSRF_SSL_STRICT': ('False', 'CSRF strict SSL'),
        'FORCE_HTTPS': ('False', 'Forçar HTTPS'),
    }

    for var, (default, desc) in env_vars.items():
        value = os.environ.get(var)
        if value:
            # Mascarar valores sensíveis
            if 'KEY' in var or 'PASSWORD' in var or 'SECRET' in var:
                display = value[:8] + "..." + value[-4:] if len(value) > 12 else "***"
            elif 'DATABASE_URL' in var:
                # Mostrar apenas o tipo de banco
                if 'postgresql' in value:
                    display = "postgresql://***"
                elif 'sqlite' in value:
                    display = value
                else:
                    display = "***"
            else:
                display = value
            print_item(var, display, "ok")
        else:
            print_item(var, f"NÃO DEFINIDA (padrão: {default})", "warn" if default else "error")

    # =========================================================================
    # 3. CONFIGURAÇÃO DO FLASK
    # =========================================================================
    print_section("3. CONFIGURAÇÃO DO FLASK")

    try:
        # Carregar configuração
        from dotenv import load_dotenv
        load_dotenv()

        from config import get_config
        config_class = get_config()

        print_item("Classe de Config", config_class.__name__, "ok")

        # Configurações críticas para CSRF
        critical_configs = [
            ('SECRET_KEY', 'set' if hasattr(config_class, 'SECRET_KEY') and config_class.SECRET_KEY else 'NOT SET'),
            ('SESSION_COOKIE_SECURE', getattr(config_class, 'SESSION_COOKIE_SECURE', 'N/A')),
            ('SESSION_COOKIE_HTTPONLY', getattr(config_class, 'SESSION_COOKIE_HTTPONLY', 'N/A')),
            ('SESSION_COOKIE_SAMESITE', getattr(config_class, 'SESSION_COOKIE_SAMESITE', 'N/A')),
            ('WTF_CSRF_ENABLED', getattr(config_class, 'WTF_CSRF_ENABLED', True)),
            ('WTF_CSRF_SSL_STRICT', getattr(config_class, 'WTF_CSRF_SSL_STRICT', False)),
            ('WTF_CSRF_TIME_LIMIT', getattr(config_class, 'WTF_CSRF_TIME_LIMIT', 3600)),
            ('PERMANENT_SESSION_LIFETIME', str(getattr(config_class, 'PERMANENT_SESSION_LIFETIME', 'N/A'))),
        ]

        for name, value in critical_configs:
            if name == 'SESSION_COOKIE_SECURE' and value == True:
                print_item(name, value, "warn")
                print("      ↳ ATENÇÃO: Cookie só funciona via HTTPS!")
            elif name == 'WTF_CSRF_SSL_STRICT' and value == True:
                print_item(name, value, "warn")
                print("      ↳ ATENÇÃO: CSRF requer SSL estrito!")
            else:
                print_item(name, value, "ok")

    except Exception as e:
        print_item("Erro ao carregar config", str(e), "error")

    # =========================================================================
    # 4. TESTE DE CONEXÃO COM BANCO
    # =========================================================================
    print_section("4. CONEXÃO COM BANCO DE DADOS")

    try:
        from config import get_config
        config = get_config()
        db_url = config.SQLALCHEMY_DATABASE_URI

        if 'postgresql' in db_url:
            print_item("Tipo", "PostgreSQL", "ok")
        elif 'sqlite' in db_url:
            print_item("Tipo", "SQLite", "ok")
        else:
            print_item("Tipo", "Outro", "warn")

        # Tentar conectar
        from flask import Flask
        from models import db, User

        app = Flask(__name__)
        app.config.from_object(config)
        db.init_app(app)

        with app.app_context():
            user_count = User.query.count()
            print_item("Conexão", "OK", "ok")
            print_item("Usuários no banco", user_count, "ok")

    except Exception as e:
        print_item("Conexão", f"FALHOU: {e}", "error")

    # =========================================================================
    # 5. VERIFICAÇÃO DE PROCESSOS
    # =========================================================================
    print_section("5. PROCESSOS E SERVIÇOS")

    try:
        import subprocess

        # Verificar se gunicorn está rodando
        try:
            result = subprocess.run(['pgrep', '-f', 'gunicorn'], capture_output=True, text=True)
            if result.stdout.strip():
                pids = result.stdout.strip().split('\n')
                print_item("Gunicorn", f"Rodando ({len(pids)} processos)", "ok")
            else:
                print_item("Gunicorn", "Não encontrado", "warn")
        except:
            print_item("Gunicorn", "Não foi possível verificar", "warn")

        # Verificar nginx
        try:
            result = subprocess.run(['pgrep', '-f', 'nginx'], capture_output=True, text=True)
            if result.stdout.strip():
                print_item("Nginx", "Rodando", "ok")
            else:
                print_item("Nginx", "Não encontrado", "warn")
        except:
            print_item("Nginx", "Não foi possível verificar", "warn")

        # Verificar porta 5000
        try:
            result = subprocess.run(['ss', '-tlnp'], capture_output=True, text=True)
            if ':5000' in result.stdout:
                print_item("Porta 5000", "Em uso", "ok")
            else:
                print_item("Porta 5000", "Livre", "warn")
        except:
            pass

    except Exception as e:
        print_item("Verificação de processos", f"Erro: {e}", "warn")

    # =========================================================================
    # 6. CONFIGURAÇÃO DO NGINX (se existir)
    # =========================================================================
    print_section("6. CONFIGURAÇÃO DO NGINX")

    nginx_configs = [
        '/etc/nginx/sites-enabled/network-backup',
        '/etc/nginx/sites-enabled/default',
        '/etc/nginx/conf.d/network-backup.conf',
    ]

    nginx_found = False
    for config_path in nginx_configs:
        if os.path.exists(config_path):
            nginx_found = True
            print_item("Arquivo encontrado", config_path, "ok")

            try:
                with open(config_path, 'r') as f:
                    content = f.read()

                # Verificar configurações importantes
                checks = [
                    ('proxy_pass', 'proxy_pass' in content),
                    ('X-Forwarded-Proto', 'X-Forwarded-Proto' in content),
                    ('X-Forwarded-For', 'X-Forwarded-For' in content),
                    ('X-Real-IP', 'X-Real-IP' in content),
                ]

                for name, present in checks:
                    if present:
                        print_item(f"  {name}", "Configurado", "ok")
                    else:
                        print_item(f"  {name}", "NÃO ENCONTRADO", "error" if name == 'X-Forwarded-Proto' else "warn")

                # Mostrar bloco location relevante
                if 'location' in content:
                    print("\n  Trecho da configuração:")
                    lines = content.split('\n')
                    in_location = False
                    for line in lines:
                        if 'location' in line:
                            in_location = True
                        if in_location:
                            print(f"    {line}")
                            if '}' in line and in_location:
                                break

            except Exception as e:
                print_item("Erro ao ler", str(e), "error")
            break

    if not nginx_found:
        print_item("Configuração Nginx", "Não encontrada nos locais padrão", "warn")

    # =========================================================================
    # 7. TESTE DE CSRF TOKEN
    # =========================================================================
    print_section("7. TESTE DE GERAÇÃO CSRF TOKEN")

    try:
        from flask import Flask
        from flask_wtf.csrf import CSRFProtect, generate_csrf
        from config import get_config

        app = Flask(__name__)
        app.config.from_object(get_config())
        csrf = CSRFProtect(app)

        with app.test_request_context():
            token = generate_csrf()
            if token:
                print_item("Geração de token", f"OK ({len(token)} chars)", "ok")
            else:
                print_item("Geração de token", "FALHOU", "error")

    except Exception as e:
        print_item("Teste CSRF", f"Erro: {e}", "error")

    # =========================================================================
    # 8. TESTE DE REQUEST SIMULADO
    # =========================================================================
    print_section("8. TESTE DE LOGIN SIMULADO")

    try:
        from flask import Flask
        from flask_wtf.csrf import CSRFProtect
        from config import get_config

        app = Flask(__name__)
        app.config.from_object(get_config())
        app.config['WTF_CSRF_ENABLED'] = True
        CSRFProtect(app)

        with app.test_client() as client:
            # Fazer GET para pegar o token
            response = client.get('/auth/login')
            print_item("GET /auth/login", f"Status {response.status_code}",
                      "ok" if response.status_code == 200 else "error")

            # Verificar se tem csrf_token na resposta
            if b'csrf_token' in response.data:
                print_item("CSRF token no HTML", "Presente", "ok")
            else:
                print_item("CSRF token no HTML", "NÃO ENCONTRADO", "error")

            # Verificar cookies
            cookies = client.cookie_jar
            session_cookie = None
            for cookie in cookies:
                if cookie.name == 'session':
                    session_cookie = cookie
                    break

            if session_cookie:
                print_item("Cookie de sessão", "Criado", "ok")
                print_item("  Secure", session_cookie.secure, "warn" if session_cookie.secure else "ok")
                print_item("  HttpOnly", session_cookie.has_nonstandard_attr('HttpOnly'), "ok")
            else:
                print_item("Cookie de sessão", "NÃO CRIADO", "error")

    except Exception as e:
        print_item("Teste de login", f"Erro: {e}", "error")

    # =========================================================================
    # 9. RECOMENDAÇÕES
    # =========================================================================
    print_section("9. RECOMENDAÇÕES")

    print("""
  Com base no diagnóstico, verifique:

  1. Se SESSION_COOKIE_SECURE=True, você DEVE acessar via HTTPS

  2. Se usa Nginx como proxy, adicione estes headers:

     proxy_set_header X-Forwarded-Proto $scheme;
     proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
     proxy_set_header X-Real-IP $remote_addr;

  3. Adicione ProxyFix no app.py após criar a app:

     from werkzeug.middleware.proxy_fix import ProxyFix
     app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

  4. Se não usa HTTPS, defina no .env:

     SESSION_COOKIE_SECURE=False
     WTF_CSRF_SSL_STRICT=False

  5. Reinicie o Gunicorn após alterações:

     sudo systemctl restart gunicorn
     # ou
     sudo systemctl restart network-backup
""")

    # =========================================================================
    # 10. INFORMAÇÕES PARA SUPORTE
    # =========================================================================
    print_section("10. COPIE ESTE RESULTADO PARA ANÁLISE")
    print("\n  Execute: python diagnostico_csrf.py > diagnostico.txt")
    print("  E envie o arquivo diagnostico.txt para análise.\n")

if __name__ == '__main__':
    main()
