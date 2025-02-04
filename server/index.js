// server/index.js
const express = require('express');
const app = express();

const cors = require('cors');
app.use(cors({
  origin: 'https://learn-sso.sloperiver.com', // クライアント側のオリジンを許可
  credentials: true // Cookie などの認証情報も許可する場合
}));

const cookieParser = require('cookie-parser');
app.use(cookieParser());

const { jwtDecrypt } = require('jose');

const PORT = process.env.PORT || 3000;

// JSON ボディのパース（JSON形式のリクエストがある場合）
app.use(express.json());
// POST の body を解析するためのミドルウェア（signout 用）
app.use(express.urlencoded({ extended: true }));

// 静的ファイルの提供（client ディレクトリ内の index.html など）
app.use(express.static('../client'));

// /api/session エンドポイント
app.get('/api/session', (req, res) => {
  const token = req.cookies['__Secure-authjs.session-token'];
  console.log(token);
  if (token) {
    try {
      // JWT を検証（例として email クレームが含まれていると想定）
      const payload = verifyJWE(token);
      return res.json({ email: payload.email });
    } catch (err) {
      console.error('JWT verification failed:', err);
      // トークンが無効の場合は 401 を返す
      return res.status(401).json({ error: 'Invalid token' });
    }
  }
  // Cookie が存在しない場合は 401
  res.status(401).json({ error: 'Not authenticated' });
});

// /signout エンドポイント（POST リクエスト）
app.post('/signout', (req, res) => {
  // 共通ドメインで発行されている Cookie を削除する
  res.clearCookie('__Secure-authjs.session-token', { domain: '.sloperiver.com', path: '/' });
  res.sendStatus(200);
});

// サーバー起動
app.listen(PORT, () => {
  console.log(`Server is running on port ${PORT}`);
});

async function verifyJWE(token) {
  try {
    // AUTH_SECRET を16進数文字列からバイナリデータに変換
    const keyBuffer = Buffer.from(process.env.AUTH_SECRET, 'hex');
    console.log('Key length in bytes:', keyBuffer.length); // 64 バイトであることを確認

    // jwtDecrypt を使ってトークンを復号
    const { payload, protectedHeader } = await jwtDecrypt(token, keyBuffer, {
      // ここでは Auth.js のデフォルト暗号アルゴリズム A256CBC-HS512 を指定
      algorithms: ['A256CBC-HS512']
    });
    
    console.log('Protected Header:', protectedHeader);
    console.log('Decoded Payload:', payload);

    return payload;
  } catch (err) {
    console.error('JWE verification failed:', err);
    throw err;
  }
}
