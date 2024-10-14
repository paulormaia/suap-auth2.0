from flask import Flask, session, redirect, url_for, request, jsonify
from requests_oauthlib import OAuth2Session
import requests
import os

app = Flask(__name__)
app.secret_key = 'minha-chave-secreta'  # Alterar para algo mais seguro em produção

# Configurações do OAuth e endpoints do SUAP
CLIENT_ID = os.environ['CLIENT_ID']
CLIENT_SECRET = os.environ['CLIENT_SECRET']
REDIRECT_URI = 'https://11c6fd84-7b8e-4d4f-8a4f-6ab779fd7953-00-3s7mc26x9hpal.riker.replit.dev/callback'
AUTHORIZATION_ENDPOINT = 'https://suap.ifrn.edu.br/o/authorize/'
TOKEN_ENDPOINT = 'https://suap.ifrn.edu.br/o/token/'
API_ME_ENDPOINT = 'https://suap.ifrn.edu.br/api/eu/'

# Função para obter o OAuth2Session com o token da sessão
def get_oauth_session(token=None):
    return OAuth2Session(CLIENT_ID, redirect_uri=REDIRECT_URI, token=token)

# Rota principal: Verifica autenticação e redireciona
@app.route('/')
def index():
    if 'access_token' in session:
        return redirect(url_for('profile'))  # Se autenticado, vai para o perfil

    return '''
        <h1>Bem-vindo</h1>
        <p>Você precisa fazer <a href="/login">login</a> para acessar seu perfil.</p>
    '''

# Rota inicial: redireciona para a página de autorização do SUAP
@app.route('/login')
def login():
    suap = get_oauth_session()
    authorization_url, state = suap.authorization_url(AUTHORIZATION_ENDPOINT)

    # Salva o estado na sessão para verificação posterior
    session['oauth_state'] = state
    return redirect(authorization_url)

# Callback: troca código de autorização por token de acesso
@app.route('/callback')
def callback():
    suap = get_oauth_session()
    authorization_code = request.args.get('code')

    if not authorization_code:
        return 'Authorization code not provided.', 400

    try:
        # Troca o código por um token
        token = suap.fetch_token(TOKEN_ENDPOINT,
                                 authorization_response=request.url,
                                 code=authorization_code,
                                 client_secret=CLIENT_SECRET)

        # Salva o token na sessão
        session['access_token'] = token
        return redirect(url_for('profile'))  # Redireciona para a página de perfil
    except Exception as e:
        print(f'Erro ao trocar o código por token: {e}')
        return 'Ocorreu um erro durante a autenticação.', 500

# Middleware: Verifica se o token está disponível na sessão
def ensure_authenticated():
    return 'access_token' in session

# Rota /profile: Exibe informações do usuário se autenticado
@app.route('/profile')
def profile():
    if not ensure_authenticated():
        return redirect(url_for('login'))  # Se não houver token, redireciona para login

    try:
        access_token = session['access_token']['access_token']
        headers = {'Authorization': f'Bearer {access_token}'}
        response = requests.get(API_ME_ENDPOINT, headers=headers)

        # Exibe as informações do usuário
        return jsonify(response.json())
    except Exception as e:
        print(f'Erro ao obter informações do usuário: {e}')
        return 'Erro ao obter dados do perfil.', 500

if __name__ == '__main__':
  app.run(host='0.0.0.0', port=8888, debug = True)
