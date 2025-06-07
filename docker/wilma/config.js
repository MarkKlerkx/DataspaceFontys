console.log

const config = {};

// Used only if https is disabled
config.pep_port = 3003;

// Set this var to undefined if you don't want the server to listen on HTTPS
config.https = {
  enabled: false,
  cert_file: 'cert/cert.crt',
  key_file: 'cert/key.key',
  port: 443,
};

config.idm = {
  host: 'keyrock',
  port: 3005,
  ssl: false,
};

config.app = {
  host: 'orion',
  port: '1026',
  ssl: false, // Use true if the app server listens in https
};

config.organizations = {
  enabled: false,
  header: 'fiware-service',
};

// Credentials obtained when registering PEP Proxy in app_id in Account Portal
config.pep = {
  app_id: 'b08a2f67-1872-4962-91d1-b630802e6ac1',
  username: 'pep_proxy_c21ca374-267c-49eb-8b51-f24e9e24787b',
  password: 'pep_proxy_3279768d-5572-424d-a498-fd9c6038b752',
  token: {
    secret: 'a2e0e6c29770561f'
  },
  trusted_apps: [],
};

// Cluster configuratie (VERPLICHT)
config.cluster = {
  type: 'manual', // 'manual' is de standaard, niet aanpassen
  number: 1
};

config.authorization = {
  enabled: true,
  pdp: 'authzforce', // Belangrijk: specificeer Authzforce als de PDP
  azf: {
    protocol: 'http',
    host: 'authzforce',
    port: 8080,
    custom_policy: undefined // Start met de standaard check (HTTP-methode + pad)
  }
};

// in seconds
config.cache_time = 300;

config.error_content_type = "application/json";

module.exports = config;