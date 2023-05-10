import express, { Express, Request, Response } from "express";
import { readFileSync } from "fs";
import { QrLoginManager } from "./qrloginmanager";
import * as QRCode from "qrcode";
import { TrueNas } from "./truenas";
import { convertPkcs12 } from "./util"

const HEADER_CLIENT_CERT_FINGERPRINT = 'X-SSL-Client-SHA1';
const HEADER_X_FORWARDED_HOST = 'X-Forwarded-Host';

const config: {
    server_port: number;
    truenas_url: string;
    truenas_api_key: string;
    cert_lifetime_days: number;
    /// SHA1 sum of lowercase, no separators
    admin_cert_subject_alt_name: string;
} = JSON.parse(readFileSync(__dirname + '/config.json').toString());

const truenas: TrueNas.Connector = new TrueNas.Connector(config.truenas_url, config.truenas_api_key);
const app: Express = express();

async function clientIsAdmin(req: Request): Promise<boolean> {
    const fingerprint = req.header(HEADER_CLIENT_CERT_FINGERPRINT);
    if (fingerprint) {
        const cert = await truenas.getCertByFingerprint(fingerprint);
        return cert.san.find((value) => {
            return value.split(':')[1] == config.admin_cert_subject_alt_name;
        }) != undefined;
    }
    return false;
}

app.get('/', async (req: Request, res: Response) => {
    let html = '<table><tbody><tr><th>Name</th><th>Valid</th><th>Fingerprint</th></tr>';
    const ca = await truenas.getAllCa();
    for (const i of ca) {
        html += `<tr><td>${i.name}</td><td>${i.from} - ${i.until}</td><td>${i.fingerprint}</td></tr>`;
    }
    html += '</tbody></table><br/>';
    html += '<a href="/me">My cert</a>';

    if (await clientIsAdmin(req)) {
        html += '\n<a href="/admin">Admin</a>';
    }

    res.send(html);
});

app.get('/me', async (req: Request, res: Response) => {
    const fingerprint = req.header(HEADER_CLIENT_CERT_FINGERPRINT);
    let cert = null;
    try {
        cert = await truenas.getCertByFingerprint(<string> fingerprint);
    } catch (e) {
        res.status(500);
        if (e instanceof Error) {
            res.send((<Error> e).message);
        }
        return;
    }

    let result = `
    <b>${cert.name}</b><br/>
    SHA1 fingerprint: ${cert.fingerprint}<br/>
    Until: ${cert.until}<br/>
    Remaining: ${Math.floor(TrueNas.certRemainingDays(cert))} days<br/>
    <form action="/renew" method="post"><button>Renew</button></form>`;

    const allCerts = await truenas.getAllCert();
    const filterDN = cert.DN;
    const matchingCerts = allCerts.filter(c => c.DN == filterDN);
    if (matchingCerts.length > 0) {
        result += 'Matching certs:<table><tbody><tr><th>Name</th><th>Download</th><th>Remaining</th></tr>';
        for (const c of matchingCerts) {
            result += `<tr><td>
                           &bull; ${c.name}
                        </td><td>
                           <a href="/pkcs12/${c.id}">pfx</a>
                        </td><td>
                            ${Math.floor(TrueNas.certRemainingDays(c))}d
                        </td></tr>`;
        }
        result += '</tbody></table>';
    }
    res.send(result);
});

app.get('/remaining', async (req: Request, res: Response) => {
    const fingerprint = req.header('X-SSL-Client-SHA1');
    try {
        const cert = await truenas.getCertByFingerprint(<string> fingerprint);
        res.type('txt');
        res.send(Math.floor(TrueNas.certRemainingDays(cert)).toString());
    } catch (e) {
        res.sendStatus(403);
        return;
    }
});

app.get('/pkcs12/:certId',async (req: Request, res: Response) => {
    let cert = null;
    try {
        cert = await truenas.getCertById(parseInt(req.params.certId));
    } catch (e) {
        res.sendStatus(404);
        return;
    }

    if (!clientIsAdmin(req)) {
        const fingerprint = req.header('X-SSL-Client-SHA1');
        const clientCert = await truenas.getCertByFingerprint(<string> fingerprint);

        if (cert.DN != clientCert.DN) {
            // don't let our users get the privkeys of other users
            res.sendStatus(403);
            return;
        }
    }

    const pkcs12 = await convertPkcs12(cert);
    if (!pkcs12) {
        res.sendStatus(500);
        return;
    }

    res.contentType('application/x-pkcs12');
    res.setHeader('Content-disposition', `attachment; filename=${cert.name}.pfx`);
    res.send(pkcs12);
});

app.post('/renew', async (req: Request, res: Response) => {
    const fingerprint = req.header('X-SSL-Client-SHA1');
    let cert;
    try {
        cert = await truenas.getCertByFingerprint(<string> fingerprint);
    } catch (e) {
        res.sendStatus(403);
        return;
    }

    // check whether we have a newer, not yet installed cert
    const allCerts = await truenas.getAllCert();
    const filterDN = cert.DN;
    const matchingCerts = allCerts.filter(c => c.DN == filterDN).sort((a, b) => b.id - a.id);
    if (matchingCerts.length > 0) {
        if (matchingCerts[0].id != cert.id) {
            // the latest cert issued for this user is newer than currently installed, just return that
            res.redirect(`/pkcs12/${matchingCerts[0].id}`);
            return;
        }
    }

    // create a new cert
    try {
        const newCert = await truenas.renewCert(cert, config.cert_lifetime_days);
        res.redirect(`/pkcs12/${newCert.id}`);
    } catch (e) {
        res.status(500);
        if (e instanceof Error) {
            res.send(e.message);
        }
    }
});

app.get('/admin', async (req: Request, res: Response) => {
    if (await clientIsAdmin(req)) {
        const allCerts = await truenas.getAllCert();
        let result = '<h1>All certificates</h1><table><tbody><tr><th>Name</th><th>Download</th><th>Remaining</th></tr>';
        for (const c of allCerts.sort((a, b) => a.name.localeCompare(b.name))) {
            result += `<tr><td>
                           &bull; ${c.name}
                        </td><td>
                           <a href="/pkcs12/${c.id}">pfx</a>
                           <a href="/admin/qrcode/${c.id}">QR</a>
                        </td><td>
                            ${Math.floor(TrueNas.certRemainingDays(c))}d
                        </td></tr>`;
        }
        result += '</tbody></table>';
        res.send(result);
    } else {
        res.sendStatus(403);
    }
});

app.get('/admin/qrcode/:certId',async (req: Request, res: Response) => {
    if (await clientIsAdmin(req)) {
        const sessionKey = QrLoginManager.getKey(parseInt(req.params.certId));
        const remainingSec = QrLoginManager.getRemainingSessionLifetimeSec(sessionKey);
        const url = `https://${req.header(HEADER_X_FORWARDED_HOST)}/qrcode/${sessionKey}`;

        res.send(`
        <h1>QR code login</h1>
        Token: <a href="${url}">${sessionKey}</a><br/>
        Token lifetime: ${remainingSec} sec<br/>

        <img src="${await QRCode.toDataURL(url, {
            scale: 10
        })}"/>\n
        <h3>Installation instructions</h3><ul>
            <li>Scan QR code on phone</li>
            <li>Open in browser & download PFX file</li>
            <li>Open file, install as <i>VPN and application user certificate</i>, do not edit name (<i>tnscm</i>)</li>
            <li>Delete file from phone</li>
        </ul>
        <script type=text/javascript>
        setTimeout(function() {
            window.location.reload();
        }, ${remainingSec + 1} * 1000);
        </script>`);
    } else {
        res.sendStatus(403);
    }
});

app.get('/qrcode/:sessionId', async (req: Request, res: Response) => {
    const certId = QrLoginManager.getCertIdBySession(req.params.sessionId);
    if (certId) {
        let cert = await truenas.getCertById(certId);

        const pkcs12 = await convertPkcs12(cert);
        if (!pkcs12) {
            res.sendStatus(500);
            return;
        }

        res.contentType('application/x-pkcs12');
        res.setHeader('Content-disposition', `attachment; filename=${cert.name}.pfx`);
        res.send(pkcs12);
    } else {
        res.send(404);
    }
});

app.listen(config.server_port);
console.log(`Listening on port ${config.server_port}...`);
