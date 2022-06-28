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

# Sign a message with the key `keyXXX`. `data` should be a hex encoded
# little-endian representation of integer value to sign.
curl -H "X-Vault-Token: <VAULT_TOKEN>" 'http://127.0.0.1:8200/v1/bjjkeys/keyXXX/sign?data=aa'

# If private key stored not under `key_data` field, it can be overridden.
curl -H "X-Vault-Token: <VAULT_TOKEN>" 'http://127.0.0.1:8200/v1/bjjkeys/keyXXX/sign?data=aa&key=priv_key'

# Import new private key into vault
vault write bjjkeys/import/key4 \
  key_type=ethereum \
  private_key=052e6bb7a24a3e0eb049d5dff3125cc52285252f33022ce8d150fcf6784a5a73
# or
vault kv put bjjkeys/import/key5 \
  key_type=babyjubjub \
  private_key=e40459d3db390b67b42d31fc89c7500b54b131a9f3acf156cfa1a24272f58900
```

## Create new random key

To create a new random key, send POST request to some path with `/random`
suffix. Optionally private key field name may be overridden with parameter
`key`. Default value for `key` is `key_data`.

Extra data may be added to key with optionally additional parameters to POST
request.

```
$ curl -X POST -H "X-Vault-Token: <VAULT_TOKEN>" \
        'http://127.0.0.1:8200/v1/bjjsecret4/keys/k1/random'
$ vault kv get bjjsecret4/keys/k1
====== Data ======
Key         Value
---         -----
key_data    bebf34257cfd2a4bc39d15707d44a287f2a6f8bee53674111d6e1b93bc378a1a


## Set custom field name for key data:

$ curl -X POST -H "X-Vault-Token: <VAULT_TOKEN>" \
        -d '{"key": "private_key"}' \
        'http://127.0.0.1:8200/v1/bjjsecret4/keys/k2/random'

$ vault kv get bjjsecret4/keys/k2
======= Data =======
Key            Value
---            -----
private_key    bebf34257cfd2a4bc39d15707d44a287f2a6f8bee53674111d6e1b93bc378a1a


## Set extra data for key:

$ curl -X POST -H "X-Vault-Token: <VAULT_TOKEN>" \
        -d '{"type": "BJJ"}' \
        'http://127.0.0.1:8200/v1/bjjsecret4/keys/k3/random'

$ vault kv get bjjsecret4/keys/k3
======= Data =======
Key        Value
---        -----
key_data   bebf34257cfd2a4bc39d15707d44a287f2a6f8bee53674111d6e1b93bc378a1a
type       BJJ
```
