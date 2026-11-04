# demo-infra-terraform

Shared Terraform for the DevOps audit assistant demo. Nothing here is applied: it exists so
the Terraform drafter has real modules, team stacks and conventions to read, and a place to
open pull requests. The repo itself belongs to the **platform** team (by name).

## Layout

- `modules/s3`: the only way to make a bucket (private, versioned, encrypted, optional expiry)
- `modules/sqs`: queues with a dead-letter queue
- `teams/<team>/`: each team's stack. The drafter writes only here, one team per folder.
- `main.tf`: the root configuration (provider and backend live here, never in team folders)
- `tools/`: CI helpers (`render/` renders tfvars from committed templates; `golint/` is Go)

## Conventions

1. Buckets go through `modules/s3`; never `aws_s3_bucket` directly.
2. Queues go through `modules/sqs`, so every queue gets a dead-letter queue.
3. Every resource carries `team = "<team id>"` in its tags (the modules take a `team` input).
4. Names are `<team>-<purpose>`, lower case with dashes.
5. No `provider` or `backend` blocks in `teams/`; no secrets in Terraform (use Secrets Manager).
