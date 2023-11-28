class CookieJar {
  cookies: Record<string, string> = {}

  addCookies(res: any) {
    const pairs = [...res.headers.entries()]
      .filter(([header]) => header === 'set-cookie')
      .map(([,cookie]) => {
        const match = cookie.match(/([^=]*)=([^;]*);.*/)

        if (!match) return ['', '']

        return [match[1], match[2]]
      })

    this.cookies = {
      ...this.cookies,
      ...Object.fromEntries(pairs),
    }
  }

  serialize() {
    return Object.entries(this.cookies)
      .map(([key, val]) => `${key}=${val}`)
      .join('; ')
  }
}

type ConstructorArg = 
  | { accessToken: string; username?: string; password?: string }
  | { accessToken?: string; username: string; password: string }

class EcoBee {
  initArg: ConstructorArg
  accessToken?: string

  constructor(arg: ConstructorArg) {
    this.initArg = arg

    if (arg.accessToken) {
      this.accessToken = arg.accessToken
    }
  }

  async _webLogin() {
    const { username, password } = this.initArg

    if (!(username && password)) {
      throw new Error('Unable to do web auth without a username or password')
    }

    const jar = new CookieJar()

    let url = new URL('https://auth.ecobee.com/authorize')
    url.searchParams.set('response_type', 'token')
    url.searchParams.set('response_mode', 'form_post')
    url.searchParams.set('client_id', '183eORFPlXyz9BbDZwqexHPBQoVjgadh')
    url.searchParams.set('redirect_uri', 'https://www.ecobee.com/home/authCallback')
    url.searchParams.set('scope', 'openid smartWrite piiWrite piiRead smartRead deleteGrants')
    url.searchParams.set('audience', 'https://prod.ecobee.com/api/v1' )

    const loginFormGetResponse = await fetch(url.toString(), {
      redirect: 'manual'
    })

    const redirTarget = loginFormGetResponse.headers.get('location') 
    jar.addCookies(loginFormGetResponse)

    if (!redirTarget) { 
      throw new Error('Requesting the login form didn\'t produce the expected redirect')
    }

    // Redir url is relative, the domain doesn't matter, we just need to extract
    // the encoded "state" value
    const state = new URL(redirTarget, 'https://foo.bar')
      .searchParams.get('state')

    if (!state) {
      throw new Error('Login form didn\'t contain a state param')
    }

    url = new URL('https://auth.ecobee.com/u/login')
    url.searchParams.set('state', state)

    const body: string = Object.entries({ state, username, password, action: 'default' })
      .map(([k, v]) => `${k}=${encodeURIComponent(v)}`)
      .join('&')

    const authFormResponse = await fetch(url.toString(), {
      method: 'POST',
      headers: {
        'Content-Type': 'application/x-www-form-urlencoded',
        'cookie': jar.serialize(),
      },
      redirect: 'manual',
      body,
    })

    const exchangeUrl = authFormResponse.headers.get('location')
    jar.addCookies(authFormResponse)
    if (!exchangeUrl) {
      throw new Error('Submitting credentials didn\'t produce the expected redirect')
    }
    const exchangeResponse = await fetch(
      new URL(exchangeUrl, 'https://auth.ecobee.com').toString(),
      {
        redirect: 'manual',
        headers: { cookie: jar.serialize() },
      },
    )

    // We get this stupid blob of HTML that has our token in it, we just need
    // to fish it out. This is terrible, but it's what we've got.
    const soup = await exchangeResponse.text()
    const token = soup.match(/name="access_token" value="([^"]+)"/)?.[1]

    if (!token) {
      throw new Error('Was unable to identify the access token from the final auth flow response')
    }

    this.accessToken = token
  }

  async _gql(query: string) {
    const response = await fetch('https://beehive.ecobee.com/graphql', {
      method: 'POST',
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${this.accessToken}`,
        'content-type': 'application/json;charset=UTF-8',
      },
      body: JSON.stringify({ query }),
    })

    const { data } = (await response.json()) as { data: any }
    return data
  }

  async _get(endpoint: string, payload: unknown): Promise<any> {
    const url = new URL('https://api.ecobee.com/1/' + endpoint)
    url.searchParams.set('format', 'json')
    url.searchParams.set('json', JSON.stringify(payload))

    const response = await fetch(url.toString(), {
      headers: {
        accept: 'application/json',
        authorization: `Bearer ${this.accessToken}`,
      }
    })

    return await response.json()
  }


  async listThermostatIds(): Promise<string[]> {
    const query = `
      query SPHomesQuery {
        homes {
          devices {
            thermostats { id }
          }
        }
        unassigned {
          thermostats { id }
        }
      }
    `

    const response = await this._gql(query)
    const thermostats: string[] = []

    response.homes.forEach((home: any) => {
      home.devices.thermostats.forEach((thermostat: any) => {
        thermostats.push(thermostat.id)
      })
    })

    response.unassigned.thermostats.forEach((thermostat: any) => {
      thermostats.push(thermostat.id)
    })

    return thermostats
  }

  async getThermostatStatus(thermostatId: string) {
    const payload = {
      selection: {
        selectionType: 'thermostats',
        selectionMatch: thermostatId,
        includeEvents: true,
        includeProgram: false,
        includeSettings: true,
        includeRuntime: true,
        includeAlerts: true,
        includeWeather: false,
        includeExtendedRuntime: true,
        includeLocation: true,
        includeHouseDetails: true,
        includeNotificationSettings: true,
        includeTechnician: true,
        includePrivacy: true,
        includeVersion: true,
        includeOemCfg: true,
        includeSecuritySettings: true,
        includeSensors: true,
        includeUtility: true,
        includeAudio: true,
      }
    }

    const data = await this._get('thermostat', payload)
    return data?.thermostatList?.[0]
  }
}

export { EcoBee }
