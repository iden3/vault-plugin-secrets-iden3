# vault-plugin-secrets-iden3

Modification of vault-plugin-secrets-kv/v1 with signing capability.

## Build plugin

```shell
cd cmd/vault-plugin-secrets-iden3
go build
```

## Install plugin

```shell
cd <path_to_vault_plugins_dir>
rm vault-plugin-secrets-iden3
# copy binary plugin to vault's plugins directory
cp <path_to_vault_plugin_secrets_bjj>/cmd/vault-plugin-secrets-iden3/vault-plugin-secrets-iden3 ./
# get sha265 of plugin binary
openssl dgst -sha256 vault-plugin-secrets-iden3
# register plugin with vault
vault plugin register -sha256=<checksum from previous step> vault-plugin-secrets-iden3
# if plugin was registered earlier, reload it.
vault plugin reload -plugin=vault-plugin-secrets-iden3
```

## Enable secret engine

```shell
vault secrets enable -path=bjjkeys vault-plugin-secrets-iden3
```

## Use of plugin

```shell
# Generate new random key.
# key_type may be either "ethereum" or "babyjubjub"
vault write bjjkeys/new/key1 key_type=ethereum
# Generate new random key annotated with some metadata.
vault write bjjkeys/new/key2 key_type=babyjubjub extra1=value1 extra2=value2

# List keys
vault list bjjkeys/keys
# Keys
# ----
# key1
# key2

# Read key data
vault read bjjkeys/keys/key2
# Key           Value
# ---           -----
# extra1         value1
# extra2         value2
# key_type       babyjubjub
# public_key     e15da94d881ce6f83dd159ea99675200a731be95fa71740a94628ed219f0690a

# Get key data with private key
vault read bjjkeys/private/key2
# Key           Value
# ---           -----
# extra1         value1
# extra2         value2
# key_type       babyjubjub
# private_key    9655feb98b2680723401867222d1250010dbd6001198ecd35333cad7a8de5a61
# public_key     e15da94d881ce6f83dd159ea99675200a731be95fa71740a94628ed219f0690a

# Move key2 to old_keys/key3
vault write bjjkeys/move/key2 dest=bjjkeys/keys/old_keys/key3

# Sign data with key.
# For BJJ key data should be a hex representation of little endian encoded int.
# For ethereum key it should be a hex encoded 32-bytes hash.
vault read bjjkeys/sign/key1 \
  data=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# Key          Value
# ---          -----
# data         0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef
# signature    cbe3edf96251643c538fe7535cd06105c20f707ae71b309d67f895d2221615e22ef64e5556f50d1d4bf879dc4f1f5a33093488843a82230a6561b9e69e08754501

# Import new private key into vault
vault write bjjkeys/import/key4 \
  key_type=ethereum \
  private_key=052e6bb7a24a3e0eb049d5dff3125cc52285252f33022ce8d150fcf6784a5a73
# or
vault kv put bjjkeys/import/key5 \
  key_type=babyjubjub \
  private_key=e40459d3db390b67b42d31fc89c7500b54b131a9f3acf156cfa1a24272f58900 \
  extra_field=value1

# Delete key
vault delete bjjsecret4/keys/old_keys/key3
```
