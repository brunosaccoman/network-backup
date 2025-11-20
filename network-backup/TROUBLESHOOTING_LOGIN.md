# Troubleshooting - Erro 400 no Login

## Sintomas

- Ao tentar fazer login, recebe erro **400 (BAD REQUEST)**
- Console do navegador mostra: `POST http://IP:PORT/auth/login 400 (BAD REQUEST)`
- Página recarrega mas não mostra mensagem de erro

---

## Causas Comuns

### 1. SECRET_KEY não configurada ou inválida

**Como verificar:**
```bash
cd /opt/network-backup
grep SECRET_KEY .env
```

**Solução:**
```bash
# Gerar nova SECRET_KEY
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))"

# Editar .env e adicionar a SECRET_KEY gerada
nano .env

# Reiniciar serviço
sudo systemctl restart network-backup
```

---

### 2. SESSION_COOKIE_SECURE=True com HTTP (sem HTTPS)

Se você está acessando via HTTP (não HTTPS), os cookies de sessão não funcionarão se `SESSION_COOKIE_SECURE=True`.

**Como verificar:**
```bash
cd /opt/network-backup
grep SESSION_COOKIE_SECURE .env
```

**Solução para desenvolvimento (HTTP):**
```bash
# Editar .env
nano .env

# Adicionar ou modificar:
SESSION_COOKIE_SECURE=False

# Reiniciar serviço
sudo systemctl restart network-backup
```

**Solução para produção (recomendado):**
Configure HTTPS com certificado SSL (Let's Encrypt):
```bash
# Instalar certbot
sudo apt install certbot python3-certbot-nginx

# Obter certificado
sudo certbot --nginx -d seu-dominio.com

# .env deve ter:
SESSION_COOKIE_SECURE=True
FORCE_HTTPS=True
```

---

### 3. CSRF Token expirado ou ausente

O token CSRF expira após 1 hora (padrão). Se a página de login ficou aberta por muito tempo, o token pode ter expirado.

**Solução:**
- Recarregue a página de login (F5 ou Ctrl+R)
- Ou use modo anônimo/privada do navegador

**Para aumentar o tempo de expiração:**
```bash
# Editar .env
nano .env

# Adicionar (tempo em segundos):
WTF_CSRF_TIME_LIMIT=7200  # 2 horas

# Reiniciar
sudo systemctl restart network-backup
```

---

### 4. Proxy Reverso (Nginx) bloqueando headers

Se você está usando Nginx como proxy reverso, ele pode estar removendo ou modificando headers necessários.

**Verificar configuração do Nginx:**
```bash
sudo nano /etc/nginx/sites-available/network-backup
```

**Configuração correta:**
```nginx
location / {
    proxy_pass http://127.0.0.1:5000;
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;

    # IMPORTANTE: Não bloquear cookies
    proxy_set_header Cookie $http_cookie;

    # Timeout para requisições longas
    proxy_connect_timeout 60s;
    proxy_send_timeout 60s;
    proxy_read_timeout 60s;
}
```

**Após modificar:**
```bash
# Testar configuração
sudo nginx -t

# Reiniciar Nginx
sudo systemctl restart nginx
```

---

### 5. Navegador bloqueando cookies

Alguns navegadores bloqueiam cookies de terceiros ou de sites sem HTTPS.

**Soluções:**

**Chrome/Edge:**
1. Abra DevTools (F12)
2. Vá para Application → Cookies
3. Verifique se há cookies para o site
4. Se não houver, verifique Settings → Privacy → Cookies

**Firefox:**
1. Abra DevTools (F12)
2. Vá para Storage → Cookies
3. Verifique se há cookies

**Solução geral:**
- Use modo anônito/privado
- Limpe cache e cookies
- Desabilite extensões que bloqueiam cookies

---

### 6. Nenhum usuário cadastrado

Se não há usuários no banco de dados, você não conseguirá fazer login.

**Verificar:**
```bash
cd /opt/network-backup
python3 manage.py list-users
```

**Criar usuário admin:**
```bash
python3 manage.py create-admin
```

---

## Script de Diagnóstico Automático

Execute o script de diagnóstico para identificar automaticamente o problema:

```bash
cd /opt/network-backup
python3 diagnostico_login.py
```

O script verificará:
- ✓ Variáveis de ambiente
- ✓ Configuração do Flask
- ✓ Conexão com banco de dados
- ✓ Usuários cadastrados
- ✓ Geração de CSRF token

---

## Verificação Manual Passo a Passo

### Passo 1: Verificar se o serviço está rodando

```bash
sudo systemctl status network-backup
```

Deve mostrar: `Active: active (running)`

### Passo 2: Verificar logs da aplicação

```bash
# Últimas 50 linhas
sudo journalctl -u network-backup -n 50 --no-pager

# Acompanhar logs em tempo real
sudo journalctl -u network-backup -f
```

Procure por erros relacionados a:
- `SECRET_KEY`
- `CSRF`
- `Session`
- `400`

### Passo 3: Verificar logs do Nginx (se aplicável)

```bash
# Logs de erro
sudo tail -f /var/log/nginx/error.log

# Logs de acesso
sudo tail -f /var/log/nginx/access.log
```

### Passo 4: Testar com curl

```bash
# Obter página de login e extrair CSRF token
curl -c cookies.txt http://192.168.99.234:8000/auth/login

# Fazer login com CSRF token
curl -b cookies.txt -c cookies.txt -X POST \
  http://192.168.99.234:8000/auth/login \
  -d "username=admin" \
  -d "password=sua_senha" \
  -d "csrf_token=TOKEN_EXTRAIDO_ACIMA"
```

Se o curl funcionar mas o navegador não, o problema é no navegador (cookies).

### Passo 5: Verificar .env

```bash
cat /opt/network-backup/.env
```

**Configuração mínima necessária:**
```bash
# Obrigatório
SECRET_KEY=<string-aleatoria-32-caracteres>
ENCRYPTION_KEY=<string-aleatoria-32-caracteres>

# Banco de dados
DATABASE_URL=postgresql://backup_user:senha@localhost/network_backup

# Para HTTP (desenvolvimento)
SESSION_COOKIE_SECURE=False
DEBUG=True
FLASK_ENV=development

# Para HTTPS (produção)
SESSION_COOKIE_SECURE=True
FORCE_HTTPS=True
FLASK_ENV=production
DEBUG=False
```

---

## Teste de Conectividade

### Verificar se a porta está acessível

```bash
# Do próprio servidor
curl http://localhost:5000/auth/login

# De outro computador (substitua IP)
curl http://192.168.99.234:8000/auth/login
```

Deve retornar HTML da página de login.

### Verificar firewall

```bash
# UFW (Ubuntu/Debian)
sudo ufw status

# Permitir porta se necessário
sudo ufw allow 8000/tcp

# iptables
sudo iptables -L -n | grep 8000
```

---

## Soluções Rápidas por Cenário

### Cenário 1: Instalação nova via Docker

```bash
cd /opt/network-backup
docker-compose down
docker-compose up -d

# Verificar logs
docker-compose logs -f app

# Criar usuário admin
docker-compose exec app python manage.py create-admin
```

### Cenário 2: Instalação manual (systemd)

```bash
# Verificar .env
cd /opt/network-backup
cat .env

# Se SECRET_KEY estiver faltando
python3 -c "import secrets; print('SECRET_KEY=' + secrets.token_urlsafe(32))" >> .env
python3 -c "import secrets; print('ENCRYPTION_KEY=' + secrets.token_urlsafe(32))" >> .env

# Reiniciar
sudo systemctl restart network-backup

# Verificar logs
sudo journalctl -u network-backup -f
```

### Cenário 3: Atrás de Nginx

```bash
# Verificar configuração Nginx
sudo nginx -t

# Verificar proxy_pass
grep proxy_pass /etc/nginx/sites-available/network-backup

# Deve apontar para: http://127.0.0.1:5000
```

---

## Ainda não funciona?

Se após todas as verificações o problema persistir:

1. **Capture logs detalhados:**
```bash
# Habilitar debug
sudo nano /opt/network-backup/.env
# Adicionar: DEBUG=True

# Reiniciar
sudo systemctl restart network-backup

# Capturar logs
sudo journalctl -u network-backup -n 100 --no-pager > debug.log

# Ver também logs do Gunicorn
cat /var/log/network-backup/*.log >> debug.log
```

2. **Teste direto com Flask (modo desenvolvimento):**
```bash
cd /opt/network-backup

# Parar serviço
sudo systemctl stop network-backup

# Rodar direto
source venv/bin/activate
export FLASK_APP=app.py
export FLASK_ENV=development
flask run --host=0.0.0.0 --port=5000

# Tentar login no navegador
# Verificar mensagens no terminal
```

3. **Verifique permissões:**
```bash
ls -la /opt/network-backup/.env
# Deve ser readable pelo usuário que roda a aplicação

# Corrigir se necessário
sudo chown network-backup:network-backup /opt/network-backup/.env
sudo chmod 600 /opt/network-backup/.env
```

---

## Contato e Suporte

Se o problema persistir após todas as tentativas:

1. Execute o script de diagnóstico: `python3 diagnostico_login.py`
2. Capture os logs: `sudo journalctl -u network-backup -n 100`
3. Capture a saída do navegador (DevTools → Console)
4. Reporte no GitHub Issues com todas as informações acima

---

**Última atualização:** 2025-11-19
**Versão:** Fase 2
