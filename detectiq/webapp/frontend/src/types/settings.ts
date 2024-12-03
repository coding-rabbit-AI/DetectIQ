export interface IntegrationCredentials {
  hostname: string;
  username?: string;
  password?: string;
  api_key?: string;
  client_id?: string;
  client_secret?: string;
  tenant_id?: string;
  cloud_id?: string;
  app?: string;
  owner?: string;
  verify_ssl: boolean;
  enabled: boolean;
  [key: string]: string | boolean | undefined;
}

export interface Settings {
  openai_api_key: string;
  rule_directories: {
    [key: string]: string;
  };
  vector_store_directories: {
    [key: string]: string;
  };
  integrations: {
    splunk: IntegrationCredentials;
    elastic: IntegrationCredentials;
    microsoft_xdr: IntegrationCredentials;
  };
}

export interface IntegrationConfig {
  enabled: boolean;
  [key: string]: any;
} 