// server/index.js
const express = require('express');
const cors = require('cors');
const cookieParser = require('cookie-parser');
const jwt = require('jsonwebtoken');

const app = express();
const PORT = process.env.PORT || 3000;

// JWT の検証に使用するシークレット（本番環境では環境変数などで管理）
const JWT_SECRET = process.env.AUTH_SECRET;

app.use(cookieParser());
// CORS の設定
app.use(cors({
    origin: 'https://learn-sso.sloperiver.com', // クライアント側のオリジンを許可
    credentials: true // Cookie などの認証情報も許可する場合
  }));
// POST の body を解析するためのミドルウェア（signout 用）
app.use(express.urlencoded({ extended: true }));

// 静的ファイルの提供（client ディレクトリ内の index.html など）
app.use(express.static('../client'));

// /api/session エンドポイント
app.get('/api/session', (req, res) => {
  const token = req.cookies['__Secure-authjs.session-token'];
  if (token) {
    try {
      // JWT を検証（例として email クレームが含まれていると想定）
      const decoded = jwt.verify(token, JWT_SECRET);
      return res.json({ email: decoded.email });
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
