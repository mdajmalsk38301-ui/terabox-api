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
import TeraBoxApp from './lib/api.js';

const app = express();
const PORT = process.env.PORT || 10000;
const NDUS_COOKIE = process.env.NDUS_COOKIE || '';
const DEST_FOLDER = '/neofly_temp';

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

app.get('/extract', async (req, res) => {
  const shareUrl = req.query.url;
  if (!shareUrl) {
    return res.status(400).json({ status: 'error', message: 'Missing url parameter' });
  }
  if (!NDUS_COOKIE) {
    return res.status(500).json({ status: 'error', message: 'Server not configured with NDUS_COOKIE' });
  }

  try {
    const surl = extractSurl(shareUrl);
    const tb = new TeraBoxApp(NDUS_COOKIE);

    // Step 1: look up the share
    const shareInfo = await tb.shortUrlInfo(surl);
    if (!shareInfo || shareInfo.errno !== 0) {
      return res.status(502).json({
        status: 'error',
        message: 'Could not read share info',
        errno: shareInfo ? shareInfo.errno : null,
        errmsg: shareInfo ? shareInfo.errmsg : null,
      });
    }

    const files = shareInfo.list || [];
    if (!files.length) {
      return res.status(404).json({ status: 'error', message: 'No files found in this share' });
    }

    const shareId = shareInfo.shareid || shareInfo.share_id;
    const fromUk = shareInfo.uk;
    const fsIds = files.map((f) => f.fs_id);

    if (!shareId || !fromUk) {
      return res.status(502).json({
        status: 'error',
        message: 'Share response missing shareid/uk — TeraBox response shape may have changed',
      });
    }

    // Step 2: check + perform transfer into our own account
    await tb.querySurlTransfer(shareId, fromUk);
    const transferResult = await tb.shareTransfer(shareId, fromUk, fsIds, DEST_FOLDER);

    if (transferResult.errno !== 0) {
      return res.status(502).json({
        status: 'error',
        message: 'Transfer to account failed',
        errno: transferResult.errno,
        errmsg: transferResult.errmsg,
      });
    }

    // Transfers are async server-side — give it a moment to land, then
    // list our destination folder to find the copied file's own fs_id.
    await new Promise((r) => setTimeout(r, 2500));

    const dirListing = await tb.getRemoteDir(DEST_FOLDER);
    if (!dirListing || dirListing.errno !== 0) {
      return res.status(502).json({
        status: 'error',
        message: 'Could not list destination folder after transfer',
        errno: dirListing ? dirListing.errno : null,
      });
    }

    const ownFiles = dirListing.list || [];
    const originalNames = new Set(files.map((f) => f.server_filename));
    const matched = ownFiles.filter((f) => originalNames.has(f.server_filename));

    if (!matched.length) {
      return res.status(502).json({
        status: 'error',
        message: 'Transferred file not found in destination folder yet — try again in a few seconds',
      });
    }

    // Step 3: get a signed direct download link for our own copy
    const ownFsIds = matched.map((f) => f.fs_id);
    const downloadResp = await tb.download(ownFsIds);

    if (!downloadResp || downloadResp.errno !== 0) {
      return res.status(502).json({
        status: 'error',
        message: 'Failed to generate download link',
        errno: downloadResp ? downloadResp.errno : null,
      });
    }

    const dlinkList = downloadResp.dlink || downloadResp.list || [];
    const result = matched.map((f, i) => ({
      filename: f.server_filename,
      size: f.size,
      download_link:
        (dlinkList[i] && (dlinkList[i].dlink || dlinkList[i])) ||
        f.dlink ||
        '',
      thumbnail: (f.thumbs && (f.thumbs.url3 || f.thumbs.icon)) || '',
    }));

    return res.json({ status: 'success', url: shareUrl, files: result });
  } catch (err) {
    console.error('Extraction error:', err);
    return res.status(500).json({ status: 'error', message: err.message });
  }
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`neofly-terabox-node listening on port ${PORT}`);
});
      
