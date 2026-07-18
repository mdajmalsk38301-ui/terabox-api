/**
 * neofly-terabox-node — Node.js TeraBox extraction service
 *
 * Instead of scraping an anonymous share link (what kept getting flagged
 * with "need verify"), this logs in with a real ndus cookie and does what
 * a human does when they tap "Save to My TeraBox" on a shared link:
 *
 *   1. Look up the share (shortUrlInfo)
 *   2. Check + perform a transfer into our own account storage
 *      (querySurlTransfer -> shareTransfer)
 *   3. List our own destination folder to find the newly-copied file's
 *      own fs_id (getRemoteDir)
 *   4. Request a signed direct download link for OUR OWN file (download)
 *
 * This is the legitimate authenticated flow, not anonymous scraping —
 * which is why it should be far less likely to trigger TeraBox's
 * anti-bot "need verify" wall.
 *
 * Env vars:
 *   NDUS_COOKIE   Your TeraBox account's ndus cookie value
 *   PORT          Provided by Render automatically
 */

import express from 'express';
import { ProxyAgent, setGlobalDispatcher } from 'undici';
import TeraBoxApp from './lib/api.js';

// If PROXY_URL is set, route every outgoing request (all of api.js's
// TeraBox calls use undici under the hood) through it. This is meant to
// get around TeraBox blocking/restricting requests from known datacenter
// IP ranges like Render's, the same issue that killed YouTube support.
//
// PROXY_URL format: http://username:password@proxyhost:port
const PROXY_URL = process.env.PROXY_URL;
if (PROXY_URL) {
  setGlobalDispatcher(new ProxyAgent(PROXY_URL));
  console.log('Routing requests through proxy:', PROXY_URL.replace(/:[^:@]+@/, ':***@'));
} else {
  console.log('No PROXY_URL set — requests will use Render\'s direct IP.');
}

const app = express();
const PORT = process.env.PORT || 10000;
const NDUS_COOKIE = process.env.NDUS_COOKIE || '';
const DEST_FOLDER = '/neofly_temp_' + Date.now();

function extractSurl(shareUrl) {
  const u = new URL(shareUrl);
  let surl;
  if (u.searchParams.has('surl')) {
    surl = u.searchParams.get('surl');
  } else if (u.pathname.includes('/s/')) {
    surl = u.pathname.split('/s/')[1].split('/')[0].split('?')[0];
  } else {
    throw new Error('Could not extract surl from URL');
  }
  if (surl.startsWith('1')) surl = surl.slice(1);
  return surl;
}

app.get('/', (req, res) => {
  res.json({ status: 'operational', name: 'neofly-terabox-node' });
});

app.get('/health', (req, res) => {
  res.json({ status: 'healthy', timestamp: new Date().toISOString() });
});

// Shared extraction logic: given an already-authenticated TeraBoxApp
// instance, look up the share, transfer it into the account, and return
// a signed direct download link for the account's own copy.
async function runExtraction(tb, shareUrl) {
  const surl = extractSurl(shareUrl);
  const destFolder = '/neofly_temp_' + Date.now();

  const shareInfo = await tb.shortUrlInfo(surl);
  if (!shareInfo || shareInfo.errno !== 0) {
    return { httpStatus: 502, body: {
      status: 'error', message: 'Could not read share info',
      errno: shareInfo ? shareInfo.errno : null, errmsg: shareInfo ? shareInfo.errmsg : null,
    }};
  }

  const files = shareInfo.list || [];
  if (!files.length) {
    return { httpStatus: 404, body: { status: 'error', message: 'No files found in this share' } };
  }

  const shareId = shareInfo.shareid || shareInfo.share_id;
  const fromUk = shareInfo.uk;
  const fsIds = files.map((f) => f.fs_id);

  if (!shareId || !fromUk) {
    return { httpStatus: 502, body: {
      status: 'error', message: 'Share response missing shareid/uk — TeraBox response shape may have changed',
    }};
  }

  const transferCheck = await tb.querySurlTransfer(shareId, fromUk);
  console.log('querySurlTransfer response:', JSON.stringify(transferCheck));
  if (!transferCheck || transferCheck.errno !== 0) {
    return { httpStatus: 502, body: {
      status: 'error', message: 'Transfer eligibility check failed',
      errno: transferCheck ? transferCheck.errno : null, raw: transferCheck,
    }};
  }

  const transferResult = await tb.shareTransfer(shareId, fromUk, fsIds, destFolder);
  console.log('shareTransfer response:', JSON.stringify(transferResult));
  if (transferResult.errno !== 0) {
    return { httpStatus: 502, body: {
      status: 'error', message: 'Transfer to account failed',
      errno: transferResult.errno, raw: transferResult,
    }};
  }

  await new Promise((r) => setTimeout(r, 2500));

  const dirListing = await tb.getRemoteDir(destFolder);
  if (!dirListing || dirListing.errno !== 0) {
    return { httpStatus: 502, body: {
      status: 'error', message: 'Could not list destination folder after transfer',
      errno: dirListing ? dirListing.errno : null,
    }};
  }

  const ownFiles = dirListing.list || [];
  const originalNames = new Set(files.map((f) => f.server_filename));
  const matched = ownFiles.filter((f) => originalNames.has(f.server_filename));

  if (!matched.length) {
    return { httpStatus: 502, body: {
      status: 'error',
      message: 'Transferred file not found in destination folder yet — try again in a few seconds',
    }};
  }

  const ownFsIds = matched.map((f) => f.fs_id);
  const downloadResp = await tb.download(ownFsIds);
  if (!downloadResp || downloadResp.errno !== 0) {
    return { httpStatus: 502, body: {
      status: 'error', message: 'Failed to generate download link',
      errno: downloadResp ? downloadResp.errno : null,
    }};
  }

  const dlinkList = downloadResp.dlink || downloadResp.list || [];
  const result = matched.map((f, i) => ({
    filename: f.server_filename,
    size: f.size,
    download_link: (dlinkList[i] && (dlinkList[i].dlink || dlinkList[i])) || f.dlink || '',
    thumbnail: (f.thumbs && (f.thumbs.url3 || f.thumbs.icon)) || '',
  }));

  return { httpStatus: 200, body: { status: 'success', url: shareUrl, files: result } };
}

// Original approach: reuse a cookie copied from your phone's browser.
app.get('/extract', async (req, res) => {
  const shareUrl = req.query.url;
  if (!shareUrl) {
    return res.status(400).json({ status: 'error', message: 'Missing url parameter' });
  }
  if (!NDUS_COOKIE) {
    return res.status(500).json({ status: 'error', message: 'Server not configured with NDUS_COOKIE' });
  }

  try {
    const tb = new TeraBoxApp(NDUS_COOKIE);
    const { httpStatus, body } = await runExtraction(tb, shareUrl);
    return res.status(httpStatus).json(body);
  } catch (err) {
    console.error('Extraction error:', err);
    return res.status(500).json({ status: 'error', message: err.message });
  }
});

// New approach: log in fresh with email/password, from THIS SAME server,
// so the session is created and used from the same IP the whole time —
// never copied from a phone's browser to a different machine. This tests
// whether today's repeated "need verify" walls were actually a
// cookie-moved-to-a-new-location security flag rather than pure IP/bot
// reputation.
app.get('/extract-login', async (req, res) => {
  const shareUrl = req.query.url;
  const email = process.env.TERABOX_EMAIL;
  const password = process.env.TERABOX_PASSWORD;

  if (!shareUrl) {
    return res.status(400).json({ status: 'error', message: 'Missing url parameter' });
  }
  if (!email || !password) {
    return res.status(500).json({
      status: 'error',
      message: 'Server not configured with TERABOX_EMAIL / TERABOX_PASSWORD',
    });
  }

  try {
    const tb = new TeraBoxApp('', 'ndus'); // start with no cookie at all

    const preLogin = await tb.passportPreLogin(email);
    console.log('passportPreLogin response:', JSON.stringify(preLogin));
    if (!preLogin || preLogin.errno !== 0) {
      return res.status(502).json({
        status: 'error', message: 'Pre-login failed', errno: preLogin ? preLogin.errno : null, raw: preLogin,
      });
    }

    const loginResult = await tb.passportLogin(preLogin.data, email, password);
    console.log('passportLogin response:', JSON.stringify(loginResult));
    if (!loginResult || loginResult.errno !== 0) {
      return res.status(502).json({
        status: 'error', message: 'Login failed', errno: loginResult ? loginResult.errno : null, raw: loginResult,
      });
    }

    // At this point tb.params.cookie should include the freshly-issued
    // ndus token, set via Set-Cookie headers during login.
    const { httpStatus, body } = await runExtraction(tb, shareUrl);
    return res.status(httpStatus).json(body);
  } catch (err) {
    console.error('Login-based extraction error:', err);
    return res.status(500).json({ status: 'error', message: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`neofly-terabox-node listening on port ${PORT}`);
});
