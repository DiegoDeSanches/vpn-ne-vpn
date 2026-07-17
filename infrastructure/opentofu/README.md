# OpenTofu operation

Use OpenTofu 1.8.x with the locked provider versions. Backend credentials come from
the operator workload identity. The backend bucket must have versioning, object lock
or equivalent retention, KMS encryption, access logging and a separate lock table.
The `.tfbackend` file contains names only and stays outside Git.

`production.tfvars.example` is inventory, not a secret file. Image IDs must be
immutable resource IDs and every release digest must come from the signed manifest.
The root checks reject shared provider, ASN, admin project or management credentials
between entry and exit, as well as reused Vault scopes.

Nodes are replaced with `create_before_destroy`; the deployment controller must
remove the old node from the signed directory and drain it first. Direct `tofu apply`
against production is break-glass only because OpenTofu cannot enforce directory
ordering by itself.

No provisioner, remote-exec, SSH key, password, private key, Vault token, certificate
or generated password is represented in this configuration. If a future provider
resource requires a secret argument, create it inside Vault/cloud KMS and reference
only its non-secret identifier, or write an ADR before proceeding.

