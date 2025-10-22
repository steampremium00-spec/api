// index.js

require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());
// ✅ CONFIGURAÇÃO DE CORS REVISADA PARA PRODUÇÃO
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
    
    // 💡 URL DE VISUALIZAÇÃO DO SEU PROJETO ADICIONADA:
    'https://project-s1qplmoesp0n6zi7xu0c.framercanvas.com',

    // 🚨 REMOVA A LINHA ABAIXO EM PRODUÇÃO! (Se ainda estiver lá, tire)
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
// 🔹 MIDDLEWARE DE AUTENTICAÇÃO
// ========================================

const verificarAutenticacao = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Token não fornecido.' });
    }
    const token = authHeader.replace('Bearer ', '');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data.user) {
      return res.status(401).json({ error: 'Token inválido ou sessão expirada.' });
    }
    req.user = data.user;
    next();
  } catch (error) {
    console.error('Erro no middleware de autenticação:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
};

const verificarAdmin = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;
    if (!authHeader) {
      return res.status(401).json({ error: 'Token não fornecido.' });
    }
    const token = authHeader.replace('Bearer ', '');
    const { data, error } = await supabase.auth.getUser(token);
    if (error || !data.user) {
      return res.status(401).json({ error: 'Token inválido.' });
    }

    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('is_admin')
      .eq('id', data.user.id)
      .single();

    if (userError) {
      console.error('Erro ao buscar dados do usuário:', userError);
      return res.status(500).json({ error: 'Erro ao verificar permissões.' });
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
// 🔹 ROTAS DE AUTENTICAÇÃO
// ========================================

// ✅ ROTA DE CADASTRO CORRIGIDA E SIMPLIFICADA (DEPENDE DO GATILHO NO BANCO)
app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    console.log('📥 Requisição de cadastro recebida:', { email });

    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    if (!validateEmail(email)) return res.status(400).json({ error: 'E-mail inválido.' });
    if (password.length < 6) return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });

    // Apenas cria o usuário na autenticação. O gatilho no banco de dados
    // irá criar o perfil na tabela 'users' automaticamente.
    const { data, error: signUpError } = await supabase.auth.signUp({ email, password });

    if (signUpError) {
      console.error('Erro no signUp do Supabase:', signUpError);
      // Retorna a mensagem de erro específica do Supabase (ex: "User already registered")
      return res.status(signUpError.status || 400).json({ error: signUpError.message });
    }

    if (!data.user) {
      return res.status(500).json({ error: 'Erro inesperado ao criar usuário.' });
    }

    console.log('✅ Usuário registrado na autenticação:', data.user.id);
    return res.status(201).json({ 
        message: 'Cadastro realizado com sucesso. Verifique seu e-mail para confirmar a conta.', 
        user: data.user 
    });

  } catch (error) {
    console.error('Erro catastrófico no /signup:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password) return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

    const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({ email, password });
    if (signInError) {
      console.error('Erro no login:', signInError);
      return res.status(400).json({ error: 'E-mail ou senha incorretos.' });
    }

    // Busca dados adicionais do perfil do usuário na tabela 'users'
    const { data: userData } = await supabase
      .from('users')
      .select('user_name, is_admin')
      .eq('id', signInData.user.id)
      .single();

    console.log('✅ Login realizado:', signInData.user.email);
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
    if (!email) return res.status(400).json({ error: 'O e-mail é obrigatório.' });
    if (!validateEmail(email)) return res.status(400).json({ error: 'E-mail inválido.' });

    const { error } = await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: 'https://signalsafe.com.br/confirma-senha', // ✅ ÚNICA MUDANÇA AQUI!
    });

    if (error) {
        console.error("Erro no forgot-password:", error);
        return res.status(500).json({ error: 'Erro ao processar a solicitação.' });
    }

    return res.status(200).json({
      message: 'Se o e-mail estiver registrado, você receberá um link de redefinição.',
    });
  } catch (error) {
    console.error('Erro no forgot-password:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { access_token, new_password } = req.body;
    if (!access_token || !new_password) return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
    if (new_password.length < 6) return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });

    // Define a sessão do usuário temporariamente usando o token do e-mail
    const { error: sessionError } = await supabase.auth.setSession({ access_token });
    if (sessionError) return res.status(400).json({ error: 'Token inválido ou expirado.' });

    // Atualiza a senha do usuário autenticado
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
// 🔹 ROTAS DE USUÁRIO (ESTABELECIMENTOS E JAMMERS)
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

        // Verifica se o usuário logado é o dono do estabelecimento
        const { data: estabelecimento, error: estabError } = await supabase
            .from('estabelecimento')
            .select('user_id')
            .eq('id', estabelecimentoId)
            .single();

        if (estabError || !estabelecimento) return res.status(404).json({ error: 'Estabelecimento não encontrado.' });
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
      return res.status(400).json({ error: 'O campo estado_jammer é obrigatório e deve ser um booleano (true/false).' });
    }

    const { data: jammerData, error: jammerError } = await supabase
      .from('jammers')
      .select('*, estabelecimento(user_id)')
      .eq('id', jammerId)
      .single();

    if (jammerError || !jammerData) return res.status(404).json({ error: 'Jammer não encontrado.' });
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
// 🔹 ROTAS DE ADMIN
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
        console.error('Erro ao listar usuários:', error);
        return res.status(500).json({ error: 'Erro ao listar usuários.' });
    }
});

app.post('/admin/estabelecimento', verificarAdmin, async (req, res) => {
    try {
        const { user_id, nome, cep } = req.body;
        if (!user_id || !nome || !cep) return res.status(400).json({ error: 'user_id, nome e cep são obrigatórios.' });

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
        const { id_estabelecimento, estado_jammer = false } = req.body; // Define false como padrão
        if (!id_estabelecimento) return res.status(400).json({ error: 'id_estabelecimento é obrigatório.' });

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
        
        // 🔹 BOA PRÁTICA: Usar transação se o Supabase permitir, ou garantir a ordem
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
// 🔹 HEALTH CHECK
// ========================================
app.get('/health', (req, res) => {
  res.status(200).json({ status: 'OK', timestamp: new Date().toISOString() });
});

// ========================================
// 🚀 INICIALIZAÇÃO DO SERVIDOR
// ========================================
const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`🚀 Servidor rodando na porta ${PORT}`));
