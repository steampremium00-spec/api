aureliú
scuttiboldao_35872
Anonymous Hacker Simulator: Prologue
+1

aureliú — 26/08/2025 18:05
https://framer.com/projects/teste--s1qpLmoeSp0n6ZI7xu0C-a2yo2
LDR Gold — 26/08/2025 18:41
calmo
LDR Gold — 26/08/2025 18:49
[Usuário Final]
       ↓
[Route 53] → Domínio personalizado (ex: armariosescola.com)
       ↓
[CloudFront] (CDN rápida e segura)
       ↓
[S3 Bucket - Frontend] ← HTML, JS, CSS do site (React, por ex.)
       ↓

        API Calls
       ↓
[API Gateway] (REST ou HTTP)
       ↓
[Amazon Cognito] ← Autenticação e tokens JWT
       ↓
[AWS Lambda Functions]
       ↓
[Amazon DynamoDB] ← Dados de usuários, armários, reservas
       ↓
[CloudWatch] ← Logs, métricas e monitoramento
       ↓
[IAM] ← Permissões entre Lambda, API, Cognito e DynamoDB
aureliú
 iniciou uma chamada que durou poucos segundos. — 26/08/2025 20:09
LDR Gold — 26/08/2025 20:10
Já entro aí  tô terminando o negócio aq
aureliú — 26/08/2025 20:10
blz
aureliú
 iniciou uma chamada que durou 20 minutos. — 03/09/2025 18:19
LDR Gold — 03/09/2025 18:24
Sistema de Gestão de Pet Shop
Tabelas e Campos
Clientes: ID_Cliente (PK), Nome, Telefone, Email

Pets: ID_Pet (PK), Nome, Especie, Raca, Idade, ID_Cliente (FK)

Servicos: ID_Servico (PK), TipoServico, DataServico, Valor, ID_Pet (FK)

Relacionamentos
Clientes (1) → (N) Pets

Pets (1) → (N) Servicos

Consultas
Listar todos os pets de um cliente

Serviços realizados em uma data específica

Receita total do pet shop no período

Formulários
Cadastro de clientes

Cadastro de pets (combobox para selecionar cliente)

Registro de serviço (combobox para selecionar pet)

Relatórios
Serviços agrupados por cliente

Receita por tipo de serviço
LDR Gold — 03/09/2025 18:39
def get_current_user():
    auth_header = request.headers.get("Authorization")
    if not auth_header:
        return None

    token = auth_header.replace("Bearer ", "")
    try:
        user = supabase.auth.get_user(token)
        return user.user
    except:
        return None


@app.route("/escolas", methods=["GET"])
def get_escolas():
    user = get_current_user()
    if not user:
        return jsonify({"error": "Não autorizado"}), 401

    res = supabase.table("estabelecimento").select("").eq("user_id", user.id).execute()
    return jsonify(res.data)




@app.route("/add_estabelecimento", methods=["PUT"])
def add_estabelecimento():
    data = request.get_json()
    ressposta = supabase.table("jammers").select("").eq("user_id", estabelecimento_id).execute()

    user = get_current_user()
    res = supabase.table("estabelecimentos").insert({
        "nome": data["nome"],
        "cep": data["ativo"],
        "user_id":user
    }).execute()

    if res.error:
        return jsonify({"error": res.error.message}), 400

    return jsonify(res.data,"Cadastrado com sucesso!"), 201






@app.route("/jammers/<estabelecimento_id>", methods=["GET"])
def get_jammers(estabelecimento_id):
    res = supabase.table("jammers").select("*").eq("user_id", estabelecimento_id).execute()

    if res.error:
        return jsonify({"error": res.error.message}), 400

    if not res.data: 
        return jsonify({"error": "Nenhum jammer encontrado"}), 404

    return jsonify(res.data)
Você perdeu uma chamada de 
LDR Gold
 que durou um minuto. — 22/09/2025 17:11
LDR Gold — 22/09/2025 17:13
liga ai
aureliú
 iniciou uma chamada que durou uma hora. — 22/09/2025 17:14
aureliú — 22/09/2025 17:16
https://framer.com/projects/teste--s1qpLmoeSp0n6ZI7xu0C-a2yo2
LDR Gold — 22/09/2025 18:05
liga ai dnv
aureliú
 iniciou uma chamada que durou 13 minutos. — 22/09/2025 18:07
LDR Gold — 22/09/2025 18:16
//Rota de redefinir senha
app.post('/forgot-password', async (req, res) => {
    const { email } = req.body;


    if (!email) {
        return res.status(400).json({ error: 'O e-mail é obrigatório.' });
    }

    try {

        const { error } = await supabase.auth.resetPasswordForEmail(email, {

            redirectTo: 'https://signalsafe.com.br/reset-password',
        });


        if (error) {
            console.error('Erro ao enviar e-mail de redefinição:', error.message);

        }

        return res.status(200).json({
            message: 'Se o e-mail estiver registrado, você receberá um link de redefinição em sua caixa de entrada.'
        });

    } catch (err) {

        console.error('Erro interno do servidor:', err);
        return res.status(500).json({ error: 'Erro interno do servidor. Tente novamente mais tarde.' });
    }
});
LDR Gold
 iniciou uma chamada que durou uma hora. — 23/09/2025 14:45
LDR Gold — 23/09/2025 15:08
https://ogyzaovpxxrzmrsoeipc.supabase.co/
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9neXphb3ZweHhyem1yc29laXBjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDcxNjA4MzAsImV4cCI6MjA2MjczNjgzMH0.mp5c80yQ8pRrn4bvK1-jUh0YCWhxgQi4z1cq-2K_ig4
aureliú — 23/09/2025 15:12
https://chatgpt.com/share/68d2e31c-57dc-8001-886a-c0d5c617a5b3
ChatGPT
ChatGPT - Componente reset senha
A conversational AI system that listens, learns, and challenges
Imagem
LDR Gold — 23/09/2025 15:37
signalsafe3@gmail.com
SignalSafe549
LDR Gold — 23/09/2025 15:46
vou comer tmb ja volto
qnd terminar te ligo
Você perdeu uma chamada de 
LDR Gold
 que durou poucos segundos. — 23/09/2025 16:23
LDR Gold — 23/09/2025 16:24
liga ai 
aureliú
 iniciou uma chamada que durou 2 horas. — 23/09/2025 16:24
aureliú — 23/09/2025 17:00
https://framer.com/projects/Untitled--UmWTG8F0JfTvZ7N4PmIL-3cJqW
https://delicate-selfie-365805.framer.app/cadastre-se
My Framer Site
Made with Framer
aureliú — 23/09/2025 17:54
https://truco-online-sinha.lovable.app/
Truco Paulista Online - Jogue com Sinais
Jogue truco paulista online com sistema de sinais intuitivo. Mesa virtual, interface brasileira e diversão garantida!
Truco Paulista Online - Jogue com Sinais
LDR Gold — 23/09/2025 17:54
Imagem
LDR Gold
 iniciou uma chamada que durou uma hora. — 07/10/2025 18:18
LDR Gold — 07/10/2025 18:21
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
Expandir
message.txt
16 KB
import * as React from "react"
import { useState, useEffect } from "react"

const API_URL = "https://supabase-auth-api-1.onrender.com"

export default function MeusEstabelecimentos() {
Expandir
message.txt
19 KB
import * as React from "react"
import { useState, useEffect } from "react"

const API_URL = "https://supabase-auth-api-1.onrender.com"

export default function AdminDashboard() {
Expandir
message.txt
41 KB
aureliú — 07/10/2025 18:23
https://chatgpt.com/share/68e584ca-f830-8001-81a1-01475192313a
ChatGPT
ChatGPT - API para signup ajustes
Shared via ChatGPT
Imagem
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
Expandir
message.txt
9 KB
LDR Gold — 07/10/2025 18:46
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');
Expandir
API_node.js
20 KB
aureliú — 07/10/2025 18:51
Imagem
LDR Gold — 07/10/2025 18:52
https://ogyzaovpxxrzmrsoeipc.supabase.co/
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9neXphb3ZweHhyem1yc29laXBjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDcxNjA4MzAsImV4cCI6MjA2MjczNjgzMH0.mp5c80yQ8pRrn4bvK1-jUh0YCWhxgQi4z1cq-2K_ig4
LDR Gold — 07/10/2025 19:04
NEXT_PUBLIC_SUPABASE_URL=https://ogyzaovpxxrzmrsoeipc.supabase.co
NEXT_PUBLIC_SUPABASE_ANON_KEY=eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJlZiI6Im9neXphb3ZweHhyem1yc29laXBjIiwicm9sZSI6ImFub24iLCJpYXQiOjE3NDcxNjA4MzAsImV4cCI6MjA2MjczNjgzMH0.mp5c80yQ8pRrn4bvK1-jUh0YCWhxgQi4z1cq-2K_ig4
BD.env.txt
1 KB
LDR Gold — 07/10/2025 19:21
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
API_node.js
20 KB
usa essa nova api
aureliú
 iniciou uma chamada que durou 3 minutos. — 07/10/2025 19:41
aureliú
 iniciou uma chamada que durou 2 horas. — 08/10/2025 19:14
aureliú — 08/10/2025 19:52
https://github.com/steampremium00-spec/api.git
GitHub
GitHub - steampremium00-spec/api
Contribute to steampremium00-spec/api development by creating an account on GitHub.
Contribute to steampremium00-spec/api development by creating an account on GitHub.
LDR Gold — 08/10/2025 20:04
{
  "name": "api-supabase",
  "version": "1.0.0",
  "description": "API Node.js com Supabase, Express, CORS e bcrypt",
  "main": "API_node.js",
  "scripts": {
    "start": "node api_node.js"
  },
  "author": "Levi Cartaginezzi",
  "license": "MIT",
  "dependencies": {
    "@supabase/supabase-js": "^2.29.0",
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bcrypt": "^5.1.1",
    "dotenv": "^16.3.1"
  }
} 
LDR Gold — 08/10/2025 20:18
{
  "name": "api-supabase",
  "version": "1.0.0",
  "description": "API Node.js com Supabase, Express, CORS e bcrypt",
  "main": "server.js",
  "scripts": {
    "start": "node server.js"
  },
  "author": "Levi Cartaginezzi",
  "license": "MIT",
  "dependencies": {
    "@supabase/supabase-js": "^2.29.0",
    "express": "^4.18.2",
    "cors": "^2.8.5",
    "bcrypt": "^5.1.1",
    "dotenv": "^16.3.1"
  }
}
https://api-1-tjtl.onrender.com/
LDR Gold — 09/10/2025 09:54
import * as React from "react"
import { useState, useEffect } from "react"

/** Carrega o script do Google Identity Services uma vez */
function useGoogleScript() {
    const [ready, setReady] = useState(false)
Expandir
message.txt
11 KB
aureliú
 iniciou uma chamada que durou poucos segundos. — 16:25
LDR Gold
 iniciou uma chamada. — 16:26
LDR Gold — 16:28
app.use(cors({
  origin: [
    'https://framer.com/',
    'https://signalsafe.com.br/',
    'https://www.signalsafe.com.br/',
    /.framer.app$/,
    /.framer.website$/,
    /.framer.site$/,
    /.framercanvas.com$/,  // ← ADICIONE ESTA LINHA!
    'http://localhost:3000/'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));
aureliú — 16:31
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
message.txt
20 KB
LDR Gold — 16:33
app.use(cors({
  origin: [
    'https://framer.com/',
    'https://signalsafe.com.br/',
    'https://www.signalsafe.com.br/',
    /.framer.app$/,
    /.framer.website$/,
    /.framer.site$/,
    /.framercanvas.com$/,
    'http://localhost:3000/'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));
aureliú — 16:34
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
message.txt
19 KB
LDR Gold — 16:38
javascriptrequire('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
message.txt
19 KB
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
message.txt
19 KB
LDR Gold — 17:00
app.use(cors({
  origin: [
    'https://framer.com/',
    'https://signalsafe.com.br/',
    'https://www.signalsafe.com.br/',
    /.framer.app$/,
    /.framer.website$/,
    /.framer.site$/,
    /.framercanvas.com$/,
    /.framer.design$/,
    /.framerusercontent.com$/,
    'http://localhost:3000/',
    '' // TEMPORÁRIO PARA TESTES - Remova depois!
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin'],
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

// Adicione isso logo após o CORS
app.options('', cors());
aureliú — 17:03
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
message.txt
20 KB
LDR Gold — 17:07
require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
Expandir
message.txt
20 KB
LDR Gold — 17:33
// index.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');
Expandir
message.txt
18 KB
﻿
// index.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// 笨� CONFIGURAﾃ�グ DE CORS REVISADA PARA PRODUﾃ�グ
app.use(cors({
  origin: [
    'https://framer.com',
    'https://signalsafe.com.br',
    'https://www.signalsafe.com.br',
    /\.framer\.app$/,
    /\.framer\.website$/,
    /\.framer\.site$/,
    /\.framercanvas\.com$/,
    /\.framer\.design$/,
    /\.framerusercontent\.com$/,
    'http://localhost:3000',
    // 圷 REMOVA A LINHA ABAIXO EM PRODUﾃ�グ!
    // '*' 
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept', 'Origin'],
  preflightContinue: false,
  optionsSuccessStatus: 204
}));

app.options('*', cors());

const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ========================================
// 隼 MIDDLEWARE DE AUTENTICAﾃ�グ
// ========================================

const verificarAutenticacao = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Token nﾃ｣o fornecido.' });
    }
    const token = authHeader.replace('Bearer ', '');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data.user) {
      return res.status(401).json({ error: 'Token invﾃ｡lido ou sessﾃ｣o expirada.' });
    }
    req.user = data.user;
    next();
  } catch (error) {
    console.error('Erro no middleware de autenticaﾃｧﾃ｣o:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
};

const verificarAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Token nﾃ｣o fornecido.' });
    }
    const token = authHeader.replace('Bearer ', '');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data.user) {
      return res.status(401).json({ error: 'Token invﾃ｡lido.' });
    }

    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('is_admin')
      .eq('id', data.user.id)
      .single();

    if (userError) {
      console.error('Erro ao buscar dados do usuﾃ｡rio:', userError);
      return res.status(500).json({ error: 'Erro ao verificar permissﾃｵes.' });
    }
    if (!userData || !userData.is_admin) {
      return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });
    }
    req.user = data.user;
    next();
  } catch (error) {
    console.error('Erro no middleware admin:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
};

// ========================================
// 隼 ROTAS DE AUTENTICAﾃ�グ
// ========================================

// 笨� ROTA DE CADASTRO CORRIGIDA E SIMPLIFICADA (DEPENDE DO GATILHO NO BANCO)
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('踏 Requisiﾃｧﾃ｣o de cadastro recebida:', { email });

    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha sﾃ｣o obrigatﾃｳrios.' });
    if (!validateEmail(email)) return res.status(400).json({ error: 'E-mail invﾃ｡lido.' });
    if (password.length < 6) return res.status(400).json({ error: 'A senha deve ter no mﾃｭnimo 6 caracteres.' });

    // Apenas cria o usuﾃ｡rio na autenticaﾃｧﾃ｣o. O gatilho no banco de dados
    // irﾃ｡ criar o perfil na tabela 'users' automaticamente.
    const { data, error: signUpError } = await supabase.auth.signUp({ email, password });

    if (signUpError) {
      console.error('Erro no signUp do Supabase:', signUpError);
      // Retorna a mensagem de erro especﾃｭfica do Supabase (ex: "User already registered")
      return res.status(signUpError.status || 400).json({ error: signUpError.message });
    }

    if (!data.user) {
      return res.status(500).json({ error: 'Erro inesperado ao criar usuﾃ｡rio.' });
    }

    console.log('笨� Usuﾃ｡rio registrado na autenticaﾃｧﾃ｣o:', data.user.id);
    return res.status(201).json({ 
        message: 'Cadastro realizado com sucesso. Verifique seu e-mail para confirmar a conta.', 
        user: data.user 
    });

  } catch (error) {
    console.error('Erro catastrﾃｳfico no /signup:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha sﾃ｣o obrigatﾃｳrios.' });

    const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({ email, password });
    if (signInError) {
      console.error('Erro no login:', signInError);
      return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
    }

    // Busca dados adicionais do perfil do usuﾃ｡rio na tabela 'users'
    const { data: userData } = await supabase
      .from('users')
      .select('user_name, is_admin')
      .eq('id', signInData.user.id)
      .single();

    console.log('笨� Login realizado:', signInData.user.email);
    return res.status(200).json({
      message: 'Login realizado com sucesso.',
      session: signInData.session,
      user: { ...signInData.user, ...userData },
    });
  } catch (error) {
    console.error('Erro no login:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/forgot-password', async (req, res) => {
  try {
    const { email } = req.body;
    if (!email) return res.status(400).json({ error: 'O e-mail ﾃｩ obrigatﾃｳrio.' });
    if (!validateEmail(email)) return res.status(400).json({ error: 'E-mail invﾃ｡lido.' });

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: 'https://signalsafe.com.br/reset-password', // 隼 BOA PRﾃゝICA: Mover para variﾃ｡vel de ambiente
    });

    if (error) {
        console.error("Erro no forgot-password:", error);
        return res.status(500).json({ error: 'Erro ao processar a solicitaﾃｧﾃ｣o.' });
    }

    return res.status(200).json({
      message: 'Se o e-mail estiver registrado, vocﾃｪ receberﾃ｡ um link de redefiniﾃｧﾃ｣o.',
    });
  } catch (error) {
    console.error('Erro no forgot-password:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { access_token, new_password } = req.body;
    if (!access_token || !new_password) return res.status(400).json({ error: 'Token e nova senha sﾃ｣o obrigatﾃｳrios.' });
    if (new_password.length < 6) return res.status(400).json({ error: 'A senha deve ter no mﾃｭnimo 6 caracteres.' });

    // Define a sessﾃ｣o do usuﾃ｡rio temporariamente usando o token do e-mail
    const { error: sessionError } = await supabase.auth.setSession({ access_token });
    if (sessionError) return res.status(400).json({ error: 'Token invﾃ｡lido ou expirado.' });

    // Atualiza a senha do usuﾃ｡rio autenticado
    const { error: updateError } = await supabase.auth.updateUser({ password: new_password });
    if (updateError) return res.status(400).json({ error: 'Erro ao atualizar senha.' });

    return res.status(200).json({ message: 'Senha atualizada com sucesso.' });
  } catch (error) {
    console.error('Erro no reset-password:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});


app.get('/verify-session', verificarAutenticacao, async (req, res) => {
  res.status(200).json({ user: req.user });
});

// ========================================
// 隼 ROTAS DE USUﾃヽIO (ESTABELECIMENTOS E JAMMERS)
// ========================================

app.get('/user/:userId/estabelecimentos', verificarAutenticacao, async (req, res) => {
  try {
    const { userId } = req.params;
    if (req.user.id !== userId) {
      return res.status(403).json({ error: 'Acesso negado.' });
    }

    const { data, error } = await supabase
      .from('estabelecimento')
      .select('*')
      .eq('user_id', userId)
      .order('nome', { ascending: true });

    if (error) throw error;
    return res.status(200).json({ estabelecimentos: data || [] });
  } catch (error) {
    console.error('Erro ao buscar estabelecimentos:', error);
    return res.status(500).json({ error: 'Erro ao buscar estabelecimentos.' });
  }
});

app.get('/user/:userId/estabelecimentos-completo', verificarAutenticacao, async (req, res) => {
    try {
        const { userId } = req.params;
        if (req.user.id !== userId) {
            return res.status(403).json({ error: 'Acesso negado.' });
        }

        const { data, error } = await supabase
            .from('estabelecimento')
            .select('*, jammers (*)')
            .eq('user_id', userId)
            .order('nome', { ascending: true });

        if (error) throw error;

        const estabelecimentosComTotais = (data || []).map(estab => ({
            ...estab,
            total_jammers: estab.jammers?.length || 0
        }));

        return res.status(200).json({
            estabelecimentos: estabelecimentosComTotais,
            total_estabelecimentos: estabelecimentosComTotais.length
        });
    } catch (error) {
        console.error('Erro ao buscar dados completos:', error);
        return res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});


app.get('/estabelecimento/:estabelecimentoId/jammers', verificarAutenticacao, async (req, res) => {
    try {
        const { estabelecimentoId } = req.params;

        // Verifica se o usuﾃ｡rio logado ﾃｩ o dono do estabelecimento
        const { data: estabelecimento, error: estabError } = await supabase
            .from('estabelecimento')
            .select('user_id')
            .eq('id', estabelecimentoId)
            .single();

        if (estabError || !estabelecimento) return res.status(404).json({ error: 'Estabelecimento nﾃ｣o encontrado.' });
        if (estabelecimento.user_id !== req.user.id) return res.status(403).json({ error: 'Acesso negado.' });

        const { data, error } = await supabase
            .from('jammers')
            .select('*')
            .eq('id_estabelecimento', estabelecimentoId)
            .order('id', { ascending: true });

        if (error) throw error;
        return res.status(200).json({ jammers: data || [] });
    } catch (error) {
        console.error('Erro ao buscar jammers:', error);
        return res.status(500).json({ error: 'Erro interno do servidor.' });
    }
});


app.patch('/jammer/:jammerId', verificarAutenticacao, async (req, res) => {
  try {
    const { jammerId } = req.params;
    const { estado_jammer } = req.body;

    if (typeof estado_jammer !== 'boolean') {
      return res.status(400).json({ error: 'O campo estado_jammer ﾃｩ obrigatﾃｳrio e deve ser um booleano (true/false).' });
    }

    const { data: jammerData, error: jammerError } = await supabase
      .from('jammers')
      .select('*, estabelecimento(user_id)')
      .eq('id', jammerId)
      .single();

    if (jammerError || !jammerData) return res.status(404).json({ error: 'Jammer nﾃ｣o encontrado.' });
    if (jammerData.estabelecimento.user_id !== req.user.id) return res.status(403).json({ error: 'Acesso negado.' });

    const { data, error } = await supabase
      .from('jammers')
      .update({ estado_jammer })
      .eq('id', jammerId)
      .select()
      .single();

    if (error) throw error;
    return res.status(200).json({ message: 'Jammer atualizado com sucesso.', jammer: data });
  } catch (error) {
    console.error('Erro ao atualizar jammer:', error);
    return res.status(500).json({ error: 'Erro ao atualizar jammer.' });
  }
});

// ========================================
// 隼 ROTAS DE ADMIN
// ========================================

app.get('/admin/usuarios', verificarAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('users')
            .select('id, email, user_name, is_admin, auth_id')
            .order('email', { ascending: true });
        if (error) throw error;
        return res.status(200).json({ usuarios: data || [] });
    } catch (error) {
        console.error('Erro ao listar usuﾃ｡rios:', error);
        return res.status(500).json({ error: 'Erro ao listar usuﾃ｡rios.' });
    }
});

app.post('/admin/estabelecimento', verificarAdmin, async (req, res) => {
    try {
        const { user_id, nome, cep } = req.body;
        if (!user_id || !nome || !cep) return res.status(400).json({ error: 'user_id, nome e cep sﾃ｣o obrigatﾃｳrios.' });

        const { data, error } = await supabase
            .from('estabelecimento')
            .insert([{ user_id, nome, cep }])
            .select()
            .single();

        if (error) throw error;
        return res.status(201).json({ message: 'Estabelecimento criado com sucesso.', estabelecimento: data });
    } catch (error) {
        console.error('Erro ao criar estabelecimento:', error);
        return res.status(500).json({ error: 'Erro ao criar estabelecimento.' });
    }
});

app.post('/admin/jammer', verificarAdmin, async (req, res) => {
    try {
        const { id_estabelecimento, estado_jammer = false } = req.body; // Define false como padrﾃ｣o
        if (!id_estabelecimento) return res.status(400).json({ error: 'id_estabelecimento ﾃｩ obrigatﾃｳrio.' });

        const { data, error } = await supabase
            .from('jammers')
            .insert([{ id_estabelecimento, estado_jammer }])
            .select()
            .single();

        if (error) throw error;
        return res.status(201).json({ message: 'Jammer criado com sucesso.', jammer: data });
    } catch (error) {
        console.error('Erro ao criar jammer:', error);
        return res.status(500).json({ error: 'Erro ao criar jammer.' });
    }
});

app.get('/admin/estabelecimentos', verificarAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('estabelecimento')
            .select('*, users(email, user_name)')
            .order('nome', { ascending: true });
        if (error) throw error;
        return res.status(200).json({ estabelecimentos: data || [] });
    } catch (error) {
        console.error('Erro ao listar estabelecimentos:', error);
        return res.status(500).json({ error: 'Erro ao listar estabelecimentos.' });
    }
});

app.get('/admin/jammers', verificarAdmin, async (req, res) => {
    try {
        const { data, error } = await supabase
            .from('jammers')
            .select('*, estabelecimento(nome, cep, users(email, user_name))')
            .order('id', { ascending: true });
        if (error) throw error;
        return res.status(200).json({ jammers: data || [] });
    } catch (error) {
        console.error('Erro ao listar jammers:', error);
        return res.status(500).json({ error: 'Erro ao listar jammers.' });
    }
});

app.delete('/admin/estabelecimento/:id', verificarAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        
        // 隼 BOA PRﾃゝICA: Usar transaﾃｧﾃ｣o se o Supabase permitir, ou garantir a ordem
        // Primeiro deleta os filhos (jammers)
        const { error: jammerError } = await supabase.from('jammers').delete().eq('id_estabelecimento', id);
        if (jammerError) throw jammerError;

        // Depois deleta o pai (estabelecimento)
        const { data, error } = await supabase.from('estabelecimento').delete().eq('id', id).select().single();
        if (error) throw error;

        return res.status(200).json({ message: 'Estabelecimento e jammers deletados.', estabelecimento: data });
    } catch (error) {
        console.error('Erro ao deletar estabelecimento:', error);
        return res.status(500).json({ error: 'Erro ao deletar estabelecimento.' });
    }
});

app.delete('/admin/jammer/:id', verificarAdmin, async (req, res) => {
    try {
        const { id } = req.params;
        const { data, error } = await supabase.from('jammers').delete().eq('id', id).select().single();
        if (error) throw error;
        return res.status(200).json({ message: 'Jammer deletado com sucesso.', jammer: data });
    } catch (error) {
        console.error('Erro ao deletar jammer:', error);
        return res.status(500).json({ error: 'Erro ao deletar jammer.' });
    }
});

// ========================================
// 隼 HEALTH CHECK
// ========================================
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ========================================
// 噫 INICIALIZAﾃ�グ DO SERVIDOR
// ========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`噫 Servidor rodando na porta ${PORT}`));
message.txt
18 KB
