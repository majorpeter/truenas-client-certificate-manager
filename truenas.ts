import axios from "axios";

/**
 * TrueNAS API v2 wrapper
 */
export namespace TrueNas {

export interface Cert {
    id: number,
    type: number,
    name: string,
    certificate: string,
    /// SHA1 sum, uppercase, separated by ':'
    fingerprint: string,
    from: string,
    until: string,
};

export function certRemainingDays(cert: Cert): number {
    const end = new Date(cert.until);
    const now = new Date();
    return (+end - +now) / (24 * 3600e3);
}

export class Connector {
    server_url: string;
    api_key: string;

    constructor(server_url: string, api_key: string) {
        this.server_url = server_url;
        this.api_key = api_key;
    }

    get api(): string {
        return this.server_url + 'api/v2.0';
    }

    get auth(): NodeJS.Dict<string> {
        return {'Authorization': 'Bearer ' + this.api_key};
    }

    async getAllCa(): Promise<{
        id: number,
        type: number,
        name: string,
        email: string,
        DN: string,
        fingerprint: string,
        certificate: string,
        from: string,
        until: string
        // not all fields are declared
    }[]> {
        const resp = await axios.get(this.api + '/certificateauthority', {
            headers: this.auth
        })
        return resp.data;
    }

    async getAllCert(): Promise<Cert[]> {
        const resp = await axios.get(this.api + '/certificate', {
            headers: this.auth
        })
        return resp.data;
    }

    /**
     * @param fingerprint SHA1 sum fingerprint of cert, lowercase, no separators
     */
    async getCertByFingerprint(fingerprint: string): Promise<Cert> {
        const certs = await this.getAllCert();
        const myCert = certs.find((value) => {
            return value.fingerprint.toLowerCase().replace(/:/g, '') == fingerprint;
        });
        if (myCert) {
            return myCert;
        }
        throw new Error('Fingerprint not found');
    }
};

}
