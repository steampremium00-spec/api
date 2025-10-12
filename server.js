require('dotenv').config();
const express = require('express');
const cors = require('cors');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// ✅ CORS CORRETO
app.use(cors({
  origin: [
    'https://framer.com',
    'https://signalsafe.com.br',
    'https://www.signalsafe.com.br',
    /\.framer\.app$/,
    /\.framer\.website$/,
    /\.framer\.site$/,
    /\.framercanvas\.com$/,
    'http://localhost:3000'
  ],
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization', 'Accept']
}));

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

app.post('/signup', async (req, res) => {
  try {
    const { email, password } = req.body;

    if (!email || !password)
      return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });
    if (!validateEmail(email))
      return res.status(400).json({ error: 'E-mail inválido.' });
    if (password.length < 6)
      return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });

    const { data: userExists } = await supabase
      .from('users')
      .select('id')
      .eq('email', email)
      .maybeSingle();

    if (userExists)
      return res.status(400).json({ error: 'E-mail já está cadastrado.' });

    const { data: signUpData, error: signUpError } = await supabase.auth.signUp({ email, password });
    if (signUpError) {
      console.error('Erro no signUp:', signUpError);
      return res.status(400).json({ error: signUpError.message });
    }

    if (!signUpData.user) {
      return res.status(400).json({ error: 'Erro ao criar usuário.' });
    }

    const userId = signUpData.user.id;

    const { error: insertError } = await supabase
      .from('users')
      .insert([{ id: userId, email, user_name: email, is_admin: false }]);

    if (insertError)
      return res.status(400).json({ error: insertError.message });

    return res.status(201).json({ message: 'Usuário cadastrado com sucesso.', userId });
  } catch (error) {
    console.error('Erro no signup:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;
    if (!email || !password)
      return res.status(400).json({ error: 'E-mail e senha são obrigatórios.' });

    const { data: signInData, error: signInError } = await supabase.auth.signInWithPassword({ email, password });
    if (signInError)
      return res.status(400).json({ error: 'E-mail ou senha incorretos.' });

    const { data: userData } = await supabase
      .from('users')
      .select('user_name, is_admin')
      .eq('id', signInData.user.id)
      .single();

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
    if (!email)
      return res.status(400).json({ error: 'O e-mail é obrigatório.' });
    if (!validateEmail(email))
      return res.status(400).json({ error: 'E-mail inválido.' });

    await supabase.auth.resetPasswordForEmail(email, {
      redirectTo: 'https://signalsafe.com.br/reset-password',
    });

    return res.status(200).json({
      message: 'Se o e-mail estiver registrado, você receberá um link de redefinição em sua caixa de entrada.',
    });
  } catch (error) {
    console.error('Erro no forgot-password:', error);
    return res.status(500).json({ error: 'Erro interno do servidor. Tente novamente mais tarde.' });
  }
});

app.post('/reset-password', async (req, res) => {
  try {
    const { access_token, new_password } = req.body;
    if (!access_token || !new_password)
      return res.status(400).json({ error: 'Token e nova senha são obrigatórios.' });
    if (new_password.length < 6)
      return res.status(400).json({ error: 'A senha deve ter no mínimo 6 caracteres.' });

    await supabase.auth.setSession({ access_token });
    const { error } = await supabase.auth.updateUser({ password: new_password });

    if (error)
      return res.status(400).json({ error: 'Erro ao atualizar senha.' });

    return res.status(200).json({ message: 'Senha atualizada com sucesso.' });
  } catch (error) {
    console.error('Erro no reset-password:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.get('/verify-session', verificarAutenticacao, async (req, res) => {
  try {
    return res.status(200).json({ user: req.user });
  } catch (error) {
    console.error('Erro no verify-session:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// ========================================
// 🔹 ROTAS DE USUÁRIO (ESTABELECIMENTOS E JAMMERS)
// ========================================

app.get('/user/:userId/estabelecimentos', verificarAutenticacao, async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user.id !== userId) {
      return res.status(403).json({ error: 'Você não tem permissão para acessar estes dados.' });
    }

    const { data: estabelecimentos, error } = await supabase
      .from('estabelecimento')
      .select('*')
      .eq('user_id', userId)
      .order('nome', { ascending: true });

    if (error) {
      console.error('Erro ao buscar estabelecimentos:', error);
      return res.status(500).json({ error: 'Erro ao buscar estabelecimentos.' });
    }

    return res.status(200).json({ 
      estabelecimentos: estabelecimentos || [], 
      total: estabelecimentos?.length || 0 
    });
  } catch (error) {
    console.error('Erro ao buscar estabelecimentos:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.get('/user/:userId/estabelecimentos-completo', verificarAutenticacao, async (req, res) => {
  try {
    const { userId } = req.params;

    if (req.user.id !== userId) {
      return res.status(403).json({ error: 'Você não tem permissão para acessar estes dados.' });
    }

    const { data: estabelecimentos, error } = await supabase
      .from('estabelecimento')
      .select(`
        *,
        jammers (*)
      `)
      .eq('user_id', userId)
      .order('nome', { ascending: true });

    if (error) {
      console.error('Erro ao buscar dados completos:', error);
      return res.status(500).json({ error: 'Erro ao buscar dados completos.' });
    }

    const estabelecimentosComTotais = (estabelecimentos || []).map(estab => ({
      ...estab,
      total_jammers: estab.jammers?.length || 0
    }));

    return res.status(200).json({ 
      estabelecimentos: estabelecimentosComTotais,
      total_estabelecimentos: estabelecimentosComTotais.length,
      total_jammers: estabelecimentosComTotais.reduce((acc, e) => acc + e.total_jammers, 0)
    });
  } catch (error) {
    console.error('Erro ao buscar dados completos:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.get('/estabelecimento/:estabelecimentoId/jammers', verificarAutenticacao, async (req, res) => {
  try {
    const { estabelecimentoId } = req.params;

    const { data: estabelecimento, error: estabError } = await supabase
      .from('estabelecimento')
      .select('user_id')
      .eq('id', estabelecimentoId)
      .single();

    if (estabError || !estabelecimento) {
      return res.status(404).json({ error: 'Estabelecimento não encontrado.' });
    }

    if (estabelecimento.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Você não tem permissão para acessar estes dados.' });
    }

    const { data, error } = await supabase
      .from('jammers')
      .select('*')
      .eq('id_estabelecimento', estabelecimentoId)
      .order('id', { ascending: true });

    if (error) return res.status(500).json({ error: 'Erro ao buscar jammers.' });
    return res.status(200).json({ jammers: data || [], total: data?.length || 0 });
  } catch (error) {
    console.error('Erro ao buscar jammers:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.patch('/jammer/:jammerId', verificarAutenticacao, async (req, res) => {
  try {
    const { jammerId } = req.params;
    const { estado_jammer } = req.body;

    if (estado_jammer === undefined) {
      return res.status(400).json({ error: 'estado_jammer é obrigatório.' });
    }

    const { data: jammerData, error: jammerError } = await supabase
      .from('jammers')
      .select(`
        *,
        estabelecimento (
          user_id
        )
      `)
      .eq('id', jammerId)
      .single();

    if (jammerError || !jammerData) {
      console.error('Erro ao buscar jammer:', jammerError);
      return res.status(404).json({ error: 'Jammer não encontrado.' });
    }

    if (jammerData.estabelecimento.user_id !== req.user.id) {
      return res.status(403).json({ error: 'Você não tem permissão para alterar este jammer.' });
    }

    const { data: updatedJammer, error } = await supabase
      .from('jammers')
      .update({ estado_jammer })
      .eq('id', jammerId)
      .select()
      .single();

    if (error) {
      console.error('Erro ao atualizar jammer:', error);
      return res.status(400).json({ error: error.message });
    }

    return res.status(200).json({ 
      message: 'Jammer atualizado com sucesso.',
      jammer: updatedJammer
    });
  } catch (error) {
    console.error('Erro interno ao atualizar jammer:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// ========================================
// 🔹 ROTAS DE ADMIN
// ========================================

app.get('/admin/usuarios', verificarAdmin, async (req, res) => {
  try {
    const { data: usuarios, error } = await supabase
      .from('users')
      .select('id, email, user_name, is_admin, auth_id')
      .order('email', { ascending: true });

    if (error) {
      console.error('Erro ao listar usuários:', error);
      return res.status(500).json({ error: 'Erro ao listar usuários.' });
    }

    return res.status(200).json({ 
      usuarios: usuarios || [],
      total: usuarios?.length || 0
    });
  } catch (error) {
    console.error('Erro interno ao listar usuários:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/admin/estabelecimento', verificarAdmin, async (req, res) => {
  try {
    const { user_id, nome, cep } = req.body;
    if (!user_id || !nome || !cep)
      return res.status(400).json({ error: 'user_id, nome e cep são obrigatórios.' });

    const { data: userExists, error: userError } = await supabase
      .from('users')
      .select('id, email')
      .eq('id', user_id)
      .single();

    if (userError || !userExists) 
      return res.status(404).json({ error: 'Usuário não encontrado.' });

    const { data, error } = await supabase
      .from('estabelecimento')
      .insert([{ user_id, nome, cep }])
      .select()
      .single();

    if (error) {
      console.error('Erro ao criar estabelecimento:', error);
      return res.status(400).json({ error: error.message });
    }

    return res.status(201).json({
      message: `Estabelecimento "${nome}" criado com sucesso para ${userExists.email}.`,
      estabelecimento: data,
    });
  } catch (error) {
    console.error('Erro interno ao criar estabelecimento:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.post('/admin/jammer', verificarAdmin, async (req, res) => {
  try {
    const { id_estabelecimento, estado_jammer } = req.body;

    if (!id_estabelecimento) {
      return res.status(400).json({ error: 'id_estabelecimento é obrigatório.' });
    }

    const { data: estabExists, error: estabError } = await supabase
      .from('estabelecimento')
      .select(`
        id,
        nome,
        user_id,
        users (
          email
        )
      `)
      .eq('id', id_estabelecimento)
      .single();

    if (estabError || !estabExists) {
      return res.status(404).json({ error: 'Estabelecimento não encontrado.' });
    }

    const { data, error } = await supabase
      .from('jammers')
      .insert([{ 
        id_estabelecimento, 
        estado_jammer: estado_jammer ?? false 
      }])
      .select()
      .single();

    if (error) {
      console.error('Erro ao criar jammer:', error);
      return res.status(400).json({ error: error.message });
    }

    return res.status(201).json({ 
      message: `Jammer criado com sucesso para "${estabExists.nome}".`,
      jammer: data,
      estabelecimento: estabExists
    });
  } catch (error) {
    console.error('Erro interno ao criar jammer:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.get('/admin/estabelecimentos', verificarAdmin, async (req, res) => {
  try {
    const { data: estabelecimentos, error } = await supabase
      .from('estabelecimento')
      .select(`
        *,
        users (
          email,
          user_name
        )
      `)
      .order('nome', { ascending: true });

    if (error) {
      console.error('Erro ao listar estabelecimentos:', error);
      return res.status(500).json({ error: 'Erro ao listar estabelecimentos.' });
    }

    return res.status(200).json({ 
      estabelecimentos: estabelecimentos || [],
      total: estabelecimentos?.length || 0
    });
  } catch (error) {
    console.error('Erro interno ao listar estabelecimentos:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.get('/admin/jammers', verificarAdmin, async (req, res) => {
  try {
    const { data: jammers, error } = await supabase
      .from('jammers')
      .select(`
        *,
        estabelecimento (
          id,
          nome,
          cep,
          user_id,
          users (
            email,
            user_name
          )
        )
      `)
      .order('id', { ascending: true });

    if (error) {
      console.error('Erro ao listar jammers:', error);
      return res.status(500).json({ error: 'Erro ao listar jammers.' });
    }

    return res.status(200).json({ 
      jammers: jammers || [],
      total: jammers?.length || 0
    });
  } catch (error) {
    console.error('Erro interno ao listar jammers:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.delete('/admin/estabelecimento/:id', verificarAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    await supabase
      .from('jammers')
      .delete()
      .eq('id_estabelecimento', id);

    const { data, error } = await supabase
      .from('estabelecimento')
      .delete()
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('Erro ao deletar estabelecimento:', error);
      return res.status(400).json({ error: error.message });
    }

    return res.status(200).json({ 
      message: 'Estabelecimento e seus jammers deletados com sucesso.',
      estabelecimento: data
    });
  } catch (error) {
    console.error('Erro interno ao deletar estabelecimento:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

app.delete('/admin/jammer/:id', verificarAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    const { data, error } = await supabase
      .from('jammers')
      .delete()
      .eq('id', id)
      .select()
      .single();

    if (error) {
      console.error('Erro ao deletar jammer:', error);
      return res.status(400).json({ error: error.message });
    }

    return res.status(200).json({ 
      message: 'Jammer deletado com sucesso.',
      jammer: data
    });
  } catch (error) {
    console.error('Erro interno ao deletar jammer:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
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
