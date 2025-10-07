require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcrypt');
const { createClient } = require('@supabase/supabase-js');

const app = express();
app.use(express.json());

// ✅ CORS configurado para Render e Framer
app.use(cors({
  origin: [
    'https://framer.com', 
    'https://signalsafe.com.br',
    /\.framer\.app$/,  // Permite qualquer subdomínio framer.app
    /\.framer\.website$/,  // Permite preview do Framer
    'http://localhost:3000'
  ],
  credentials: true,
}));

// ✅ Conexão Supabase
const supabase = createClient(process.env.SUPABASE_URL, process.env.SUPABASE_ANON_KEY);

// ✅ Função auxiliar
const validateEmail = (email) => /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);

// ========================================
// 🔹 ROTAS DE AUTENTICAÇÃO
// ========================================

// 🟢 Cadastro
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

// 🟢 Login
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

// 🟢 Esqueci minha senha
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

// 🟢 Redefinir senha
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

// 🟢 Verificação de sessão
app.get('/verify-session', async (req, res) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token)
      return res.status(401).json({ error: 'Token não fornecido.' });

    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user)
      return res.status(401).json({ error: 'Sessão inválida.' });

    return res.status(200).json({ user });
  } catch (error) {
    console.error('Erro no verify-session:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// ========================================
// 🔹 ROTAS DE USUÁRIO (ESTABELECIMENTOS E JAMMERS)
// ========================================

// 🟢 Buscar estabelecimentos do usuário
app.get('/user/:userId/estabelecimentos', async (req, res) => {
  try {
    const { userId } = req.params;

    // Verificar autenticação
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Token não fornecido.' });
    }

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      return res.status(401).json({ error: 'Token inválido.' });
    }

    // Verificar se está buscando os próprios dados
    if (user.id !== userId) {
      return res.status(403).json({ error: 'Você não tem permissão para acessar estes dados.' });
    }

    const { data, error } = await supabase
      .from('estabelecimento')
      .select('*')
      .eq('user_id', userId)
      .order('nome', { ascending: true });

    if (error) return res.status(500).json({ error: 'Erro ao buscar estabelecimentos.' });
    return res.status(200).json({ estabelecimentos: data || [], total: data?.length || 0 });
  } catch (error) {
    console.error('Erro ao buscar estabelecimentos:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// 🟢 Buscar estabelecimentos completos (com jammers)
app.get('/user/:userId/estabelecimentos-completo', async (req, res) => {
  try {
    const { userId } = req.params;

    const { data: estabelecimentos, error: estabError } = await supabase
      .from('estabelecimento')
      .select('*')
      .eq('user_id', userId)
      .order('nome', { ascending: true });

    if (estabError) {
      console.error('Erro ao buscar estabelecimentos:', estabError);
      return res.status(500).json({ error: 'Erro ao buscar estabelecimentos.' });
    }

    const estabelecimentosComJammers = await Promise.all(
      (estabelecimentos || []).map(async (estab) => {
        const { data: jammers, error: jammersError } = await supabase
          .from('jammers')
          .select('*')
          .eq('id_estabelecimento', estab.id)
          .order('id', { ascending: true });

        if (jammersError) {
          console.error(`Erro ao buscar jammers do estabelecimento ${estab.id}:`, jammersError);
          return { ...estab, jammers: [], total_jammers: 0 };
        }

        return {
          ...estab,
          jammers: jammers || [],
          total_jammers: jammers?.length || 0
        };
      })
    );

    return res.status(200).json({ 
      estabelecimentos: estabelecimentosComJammers,
      total_estabelecimentos: estabelecimentosComJammers.length,
      total_jammers: estabelecimentosComJammers.reduce((acc, e) => acc + e.total_jammers, 0)
    });
  } catch (error) {
    console.error('Erro ao buscar dados completos:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// 🟢 Buscar jammers de um estabelecimento
app.get('/estabelecimento/:estabelecimentoId/jammers', async (req, res) => {
  try {
    const { estabelecimentoId } = req.params;
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

// 🟢 Atualizar estado do jammer (ligar/desligar)
app.patch('/jammer/:jammerId', async (req, res) => {
  try {
    const { jammerId } = req.params;
    const { estado_jammer } = req.body;

    if (estado_jammer === undefined) {
      return res.status(400).json({ error: 'estado_jammer é obrigatório.' });
    }

    // Verificar se o usuário é dono do jammer
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) {
      return res.status(401).json({ error: 'Token não fornecido.' });
    }

    const { data: { user }, error: authError } = await supabase.auth.getUser(token);
    if (authError || !user) {
      return res.status(401).json({ error: 'Token inválido.' });
    }

    // Verificar se o jammer pertence ao usuário
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
      return res.status(404).json({ error: 'Jammer não encontrado.' });
    }

    if (jammerData.estabelecimento.user_id !== user.id) {
      return res.status(403).json({ error: 'Você não tem permissão para alterar este jammer.' });
    }

    // Atualizar o jammer
    const { data, error } = await supabase
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
      jammer: data
    });
  } catch (error) {
    console.error('Erro interno ao atualizar jammer:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
});

// ========================================
// 🔹 MIDDLEWARE DE ADMIN
// ========================================

const verificarAdmin = async (req, res, next) => {
  try {
    const token = req.headers.authorization?.replace('Bearer ', '');
    if (!token) return res.status(401).json({ error: 'Token não fornecido.' });

    const { data: { user }, error } = await supabase.auth.getUser(token);
    if (error || !user) return res.status(401).json({ error: 'Token inválido.' });

    const { data: userData, error: userError } = await supabase
      .from('users')
      .select('is_admin')
      .eq('id', user.id)
      .single();

    if (userError || !userData?.is_admin)
      return res.status(403).json({ error: 'Acesso negado. Apenas administradores.' });

    req.user = user;
    next();
  } catch (error) {
    console.error('Erro ao verificar admin:', error);
    return res.status(500).json({ error: 'Erro interno do servidor.' });
  }
};

// ========================================
// 🔹 ROTAS DE ADMIN
// ========================================

// 🟢 Listar todos os usuários
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

// 🟢 Criar estabelecimento (admin)
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

// 🟢 Criar jammer (admin)
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

// 🟢 Listar todos os estabelecimentos (admin)
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

// 🟢 Listar todos os jammers (admin)
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

// 🟢 Deletar estabelecimento (admin)
app.delete('/admin/estabelecimento/:id', verificarAdmin, async (req, res) => {
  try {
    const { id } = req.params;

    // Deletar jammers primeiro
    await supabase
      .from('jammers')
      .delete()
      .eq('id_estabelecimento', id);

    // Deletar estabelecimento
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

// 🟢 Deletar jammer (admin)
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