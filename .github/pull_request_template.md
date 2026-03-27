## Summary

Describe what this PR does in 1-3 sentences.

## Type of change

- [ ] Bug fix
- [ ] New feature
- [ ] Breaking change
- [ ] Documentation update
- [ ] Refactoring

## Related issues

Closes #<!-- issue number -->

## Changes

-
-

## Testing

Describe how you tested these changes:

- [ ] Unit tests added/updated
- [ ] Integration tests pass (`go test ./...`)
- [ ] Manually tested with `docker compose up`

## Checklist

- [ ] Code follows the existing patterns (repository → service → handler)
- [ ] No new global state introduced
- [ ] Error handling uses `fmt.Errorf("context: %w", err)` pattern
- [ ] New endpoints are registered in `internal/api/router.go`
- [ ] New config values have defaults set in `internal/config/config.go`
