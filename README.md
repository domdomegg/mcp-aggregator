# typescript-library-template

Personal template for creating TypeScript libraries.

## Quick start

*Prequisites: Node.js, Git, and the GitHub CLI (authed). AI agents like [Claude Code](https://www.anthropic.com/claude-code) should be able to complete all these steps.*

1. Create a new repository from this template: `gh repo create <name> --template domdomegg/typescript-library-template --clone --public` (or `--private`)
2. Run the setup script: `node setup.js [--private]`
   - `--private` will prevent the package being published to NPM. Usually packages should be public and will be published, but if you're unsure ask the user.
3. Complete the TODOs in `package.json` and `README.md` (don't change anything else!)
4. Run `npm install`, then check everything works with `npm run test && npm run build && npm run lint`
5. Commit the changes with the commit message 'Initialization from template'
