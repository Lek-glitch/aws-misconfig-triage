# Runbook: Security Group Open to the Internet

**Check IDs:** SG-001 (sensitive port), SG-002 (other port)
**Severity:** Critical (SSH/RDP/DB ports) / Medium (other ports)

## What it means
An EC2 Security Group has an inbound rule allowing traffic from
`0.0.0.0/0` (i.e. any IP address on the internet) on a port that should
normally be restricted — most critically SSH (22), RDP (3389), or a
database port (3306, 5432, 27017, 6379).

## Why it matters (customer-facing explanation)
> "One of your servers currently accepts [SSH/RDP/database] connection
> attempts from anywhere on the internet, not just your office or VPN.
> Automated bots scan the entire internet address space continuously —
> exposed management ports are typically probed within minutes of going
> live. This is one of the most common initial-access vectors in breaches."

## How to verify
```bash
aws ec2 describe-security-groups \
  --group-ids <sg-id> \
  --query "SecurityGroups[].IpPermissions"
```
Look for `"CidrIp": "0.0.0.0/0"` on any sensitive port.

## Remediation steps
1. **Identify who actually needs access.** Get the real source — office IP
   range, VPN CIDR, or a bastion host — from the customer/account owner.
2. **Revoke the open rule:**
   ```bash
   aws ec2 revoke-security-group-ingress \
     --group-id <sg-id> \
     --protocol tcp --port 22 \
     --cidr 0.0.0.0/0
   ```
3. **Add a scoped rule** replacing it:
   ```bash
   aws ec2 authorize-security-group-ingress \
     --group-id <sg-id> \
     --protocol tcp --port 22 \
     --cidr <known-safe-cidr>/32
   ```
4. **For SSH/RDP specifically**, consider replacing direct access entirely
   with **AWS Systems Manager Session Manager** — it removes the need for
   an open inbound port altogether.
5. **For databases**, they should almost never be reachable from
   `0.0.0.0/0` — move them into a private subnet with access only from
   the application tier's security group (reference the SG itself as the
   source, not a CIDR).

## Prevention
- Use **AWS Config rule** `restricted-ssh` / `restricted-common-ports` to
  detect drift automatically.
- If infrastructure is managed via Terraform, add a policy check (e.g.
  `tfsec`, `checkov`) in CI to block PRs that introduce `0.0.0.0/0` on
  sensitive ports before they ever reach production.
