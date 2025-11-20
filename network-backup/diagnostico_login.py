#!/usr/bin/env python3
"""
Script de diagnóstico para problemas de login
Execute no servidor Debian para identificar a causa do erro 400
"""

import sys
import os

# Adicionar path do projeto
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def check_environment():
    """Verifica variáveis de ambiente necessárias"""
    print("=" * 60)
    print("1. VERIFICANDO VARIÁVEIS DE AMBIENTE")
    print("=" * 60)

    required_vars = {
        'SECRET_KEY': 'Chave de sessão Flask',
        'ENCRYPTION_KEY': 'Chave de criptografia',
        'DATABASE_URL': 'URL do banco de dados'
    }

    missing = []
    for var, description in required_vars.items():
        value = os.environ.get(var)
        if value:
            print(f"✓ {var}: Configurado ({description})")
            if var == 'SECRET_KEY':
                print(f"  Tamanho: {len(value)} caracteres")
        else:
            print(f"✗ {var}: FALTANDO ({description})")
            missing.append(var)

    if missing:
        print(f"\n⚠️  ATENÇÃO: Variáveis faltando: {', '.join(missing)}")
        return False

    print("\n✓ Todas as variáveis de ambiente necessárias estão configuradas")
    return True


def check_flask_config():
    """Verifica configuração do Flask"""
    print("\n" + "=" * 60)
    print("2. VERIFICANDO CONFIGURAÇÃO DO FLASK")
    print("=" * 60)

    try:
        from app import app

        print(f"✓ Flask app carregado")
        print(f"  Ambiente: {app.config.get('FLASK_ENV', 'development')}")
        print(f"  Debug: {app.config.get('DEBUG', False)}")
        print(f"  SECRET_KEY: {'Configurado' if app.config.get('SECRET_KEY') else 'FALTANDO'}")
        print(f"  WTF_CSRF_ENABLED: {app.config.get('WTF_CSRF_ENABLED', True)}")
        print(f"  WTF_CSRF_TIME_LIMIT: {app.config.get('WTF_CSRF_TIME_LIMIT', 3600)} segundos")
        print(f"  SESSION_COOKIE_SECURE: {app.config.get('SESSION_COOKIE_SECURE', False)}")
        print(f"  SESSION_COOKIE_HTTPONLY: {app.config.get('SESSION_COOKIE_HTTPONLY', True)}")
        print(f"  SESSION_COOKIE_SAMESITE: {app.config.get('SESSION_COOKIE_SAMESITE', 'Lax')}")

        # Verificar se CSRF está habilitado
        csrf_enabled = app.config.get('WTF_CSRF_ENABLED', True)
        if not csrf_enabled:
            print("\n⚠️  CSRF está DESABILITADO - isso pode causar problemas!")

        return True

    except Exception as e:
        print(f"✗ Erro ao carregar Flask app: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_database():
    """Verifica conexão com banco de dados"""
    print("\n" + "=" * 60)
    print("3. VERIFICANDO BANCO DE DADOS")
    print("=" * 60)

    try:
        from app import app, db
        from models import User

        with app.app_context():
            # Testar conexão
            db.session.execute(db.text('SELECT 1'))
            print("✓ Conexão com banco de dados OK")

            # Contar usuários
            user_count = User.query.count()
            print(f"✓ Usuários cadastrados: {user_count}")

            if user_count == 0:
                print("\n⚠️  NENHUM usuário cadastrado!")
                print("   Execute: python manage.py create-admin")
            else:
                # Listar usuários
                users = User.query.all()
                print("\nUsuários no sistema:")
                for user in users:
                    status = "Ativo" if user.active else "Inativo"
                    print(f"  - {user.username} ({user.role}) - {status}")

            return True

    except Exception as e:
        print(f"✗ Erro ao conectar ao banco: {e}")
        import traceback
        traceback.print_exc()
        return False


def check_csrf_blueprint():
    """Verifica se blueprint de autenticação está registrado"""
    print("\n" + "=" * 60)
    print("4. VERIFICANDO BLUEPRINTS E ROTAS")
    print("=" * 60)

    try:
        from app import app

        # Listar blueprints
        print("Blueprints registrados:")
        for name, blueprint in app.blueprints.items():
            print(f"  - {name}")

        # Verificar rota de login
        print("\nRotas de autenticação:")
        for rule in app.url_map.iter_rules():
            if 'auth' in rule.rule or 'login' in rule.rule:
                print(f"  {rule.methods} {rule.rule} -> {rule.endpoint}")

        return True

    except Exception as e:
        print(f"✗ Erro ao verificar blueprints: {e}")
        return False


def test_csrf_token():
    """Testa geração de CSRF token"""
    print("\n" + "=" * 60)
    print("5. TESTANDO GERAÇÃO DE CSRF TOKEN")
    print("=" * 60)

    try:
        from app import app

        with app.test_request_context():
            from flask_wtf.csrf import generate_csrf

            token = generate_csrf()
            print(f"✓ CSRF token gerado com sucesso")
            print(f"  Token: {token[:20]}...")

        return True

    except Exception as e:
        print(f"✗ Erro ao gerar CSRF token: {e}")
        import traceback
        traceback.print_exc()
        return False


def suggest_solutions():
    """Sugere soluções baseadas nos problemas encontrados"""
    print("\n" + "=" * 60)
    print("SOLUÇÕES SUGERIDAS")
    print("=" * 60)

    print("""
Se você está recebendo erro 400 (BAD REQUEST) no login, tente:

1. PROBLEMA: SECRET_KEY não está configurada
   SOLUÇÃO:
   # Gerar nova SECRET_KEY
   python -c "import secrets; print(secrets.token_urlsafe(32))"

   # Adicionar ao .env
   SECRET_KEY=<chave_gerada_acima>

   # Reiniciar aplicação
   sudo systemctl restart network-backup

2. PROBLEMA: Cookies não estão sendo salvos
   SOLUÇÃO (se usando HTTP ao invés de HTTPS):
   # No .env, adicione:
   SESSION_COOKIE_SECURE=False

   # Reiniciar aplicação
   sudo systemctl restart network-backup

3. PROBLEMA: CSRF token expirou
   SOLUÇÃO:
   # Limpar cache do navegador
   # Ou acessar em janela anônima/privada

4. PROBLEMA: Proxy reverso (Nginx) está bloqueando headers
   SOLUÇÃO:
   # Verificar configuração do Nginx
   # Garantir que proxy_set_header está correto:

   proxy_set_header Host $host;
   proxy_set_header X-Real-IP $remote_addr;
   proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
   proxy_set_header X-Forwarded-Proto $scheme;

5. PROBLEMA: Navegador está bloqueando cookies de terceiros
   SOLUÇÃO:
   # Permitir cookies no navegador
   # Ou adicionar exceção para o site

6. VERIFICAR LOGS:
   # Ver logs da aplicação
   sudo journalctl -u network-backup -n 50 --no-pager

   # Ver logs do Gunicorn
   tail -f /var/log/network-backup/gunicorn.log

   # Ver logs de acesso
   tail -f /var/log/nginx/access.log
""")


def main():
    print("DIAGNÓSTICO DE PROBLEMAS DE LOGIN - Network Backup System")
    print("=" * 60)

    results = []

    # Executar verificações
    results.append(("Variáveis de Ambiente", check_environment()))
    results.append(("Configuração Flask", check_flask_config()))
    results.append(("Banco de Dados", check_database()))
    results.append(("Blueprints e Rotas", check_csrf_blueprint()))
    results.append(("Geração CSRF Token", test_csrf_token()))

    # Resumo
    print("\n" + "=" * 60)
    print("RESUMO DO DIAGNÓSTICO")
    print("=" * 60)

    all_ok = True
    for check_name, success in results:
        status = "✓ OK" if success else "✗ FALHOU"
        print(f"{status} - {check_name}")
        if not success:
            all_ok = False

    if all_ok:
        print("\n✓ Todas as verificações passaram!")
        print("  O problema pode estar na configuração do servidor web (Nginx/Apache)")
        print("  ou no navegador (cookies bloqueados).")
    else:
        print("\n✗ Algumas verificações falharam!")
        print("  Corrija os problemas acima antes de continuar.")

    # Sugerir soluções
    suggest_solutions()


if __name__ == '__main__':
    main()
