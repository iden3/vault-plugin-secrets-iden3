# vault-plugin-secrets-bjj

Modification of vault-plugin-secrets-kv/v1 with signing capability.

## Build plugin

```shell
cd cmd/vault-plugin-secrets-bjj
go build
```

## Install plugin

```shell
cd <path_to_vault_plugins_dir>
rm vault-plugin-secrets-bjj
# copy binary plugin to vault's plugins directory
cp <path_to_vault_plugin_secrets_bjj>/cmd/vault-plugin-secrets-bjj/vault-plugin-secrets-bjj ./
# get sha265 of plugin binary
openssl dgst -sha256 vault-plugin-secrets-bjj
# register plugin with vault
vault plugin register -sha256=<checksum from previous step> vault-plugin-secrets-bjj
# if plugin was registered earlier, reload it.
vault plugin reload -plugin=vault-plugin-secrets-bjj
```

## Enable secret engine

```shell
vault secrets enable -path=bjjkeys vault-plugin-secrets-bjj
```

## Use of plugin

```shell
# Put new key into vault.
# key_data is a default key name where plugin looks for private key value.
# It can be overridden by specifying `key` param in the request.
vault kv put bjjkeys/keyXXX key_data=9c2186b8f709bb81817492a69f87ead951fc49050c7fceb6155e26a9a255dee4

# Sign a message with the key `keyXXX`
curl -H "X-Vault-Token: <VAULT_TOKEN>" 'http://127.0.0.1:8200/v1/bjjkeys/keyXXX/sign?data=aa'

# If private key stored not under `key_data` field, it can be overridden.
curl -H "X-Vault-Token: <VAULT_TOKEN>" 'http://127.0.0.1:8200/v1/bjjkeys/keyXXX/sign?data=aa&key=priv_key'
```
