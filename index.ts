import express, { Express, Request, Response } from "express";
import { readFileSync } from "fs";
import { TrueNas } from "./truenas";

const config: {
    server_port: number;
    truenas_url: string;
    truenas_api_key: string;
} = JSON.parse(readFileSync('./config.json').toString());

const truenas: TrueNas = new TrueNas(config.truenas_url, config.truenas_api_key);
const app: Express = express();

app.get('/', async (req: Request, res: Response) => {
    let html = '<table><tbody><tr><th>Name</th><th>Valid</th><th>Fingerprint</th></tr>';
    const ca = await truenas.getAllCa();
    for (const i of ca) {
        html += `<tr><td>${i.name}</td><td>${i.from} - ${i.until}</td><td>${i.fingerprint}</td></tr>`;
    }
    html += '</tbody></table>';
    res.send(html);
});

app.listen(config.server_port);
