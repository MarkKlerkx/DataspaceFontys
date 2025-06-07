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
  host: 'quantumleap',
  port: '8668',
  ssl: false, // Use true if the app server listens in https
};

config.organizations = {
  enabled: false,
  header: 'fiware-service',
};

// Credentials obtained when registering PEP Proxy in app_id in Account Portal
config.pep = {
  app_id: '38405b50-c400-4b31-a2ae-dec946f83b78',
  username: 'pep_proxy_83b24b13-a626-4308-90d6-e439d7d47543',
  password: 'pep_proxy_b00c3287-bfdc-4177-8612-1c1611b36c3b',
  token: {
    secret: 'a35d5339fdf52a22'
  },
  trusted_apps: [],
};

// Cluster configuratie (VERPLICHT)
config.cluster = {
  type: 'manual', // 'manual' is de standaard, niet aanpassen
  number: 1
};

// in seconds
config.cache_time = 300;

config.error_content_type = "application/json";

module.exports = config;