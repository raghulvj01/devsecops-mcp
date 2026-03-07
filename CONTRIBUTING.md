# Contributing

## Development Workflow

1. Fork the project.
2. Create your feature branch (`git checkout -b feature/AmazingFeature`).
3. Add your tool into `tools/<domain>/`.
4. Register it via `@mcp.tool()` in `server/main.py` with `@audit_tool_call` and auth check.
5. Add tests in `tests/`.
6. Open a Pull Request.

## Maintainer Release (npm)

This repository is open source, but npm publishing is still account-scoped. Only package maintainers can publish.

1. Bump the package version in `package.json`.
2. Verify package contents:
   - `npm run pack:check`
3. Login to npm with a maintainer account:
   - `npm login`
4. Publish publicly:
   - `npm publish --access public`
5. If your npm account uses 2FA, include OTP:
   - `npm publish --access public --otp=<6-digit-code>`

For scoped packages like `@raghulm/aegis-mcp`, `--access public` is required.
