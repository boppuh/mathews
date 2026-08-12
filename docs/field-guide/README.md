# Mathews System Field Guide

This directory contains the source for the interactive Mathews documentation
site. The production site is available at
[mathews-architecture.ryanmathews10.chatgpt.site](https://mathews-architecture.ryanmathews10.chatgpt.site).

The field guide covers:

- system architecture
- task lifecycle
- authority matrix
- evidence chain
- MVP release gate
- failure and recovery
- operator runbook
- glossary

## Local development

Use Node.js 22 or newer, then run:

```bash
npm install
npm run dev
```

Run the production build and rendered-page checks with:

```bash
npm test
```

## Publishing

The `.openai/hosting.json` file binds this source tree to the existing private
Sites project. Publish from this directory through the Sites workflow only
after the exact source revision has passed `npm test`.

The static architecture page in `public/mathews-architecture.html` is the
original supplied artifact. Preserve it byte-for-byte when changing the rest of
the field guide.
