import axios from "axios";

/**
 * TrueNAS API v2 wrapper
 */
export class TrueNas {
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
};
