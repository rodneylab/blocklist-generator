<img
  src="./images/rodneylab-github-blocklist-generator.png"
  alt="Rodney Lab Blocklist Generator Git Hub banner"
/>

<p align="center">
  <a
    aria-label="Open Rodney Lab site"
    href="https://rodneylab.com"
    rel="nofollow noopener noreferrer"
  >
    <img
      alt="Rodney Lab logo"
      src="https://rodneylab.com/assets/icon.png"
      width="60"
    />
  </a>
</p>
<h1 align="center">blocklist-generator</h1>

CLI utility for generating blocklist.rpz files for use with firewalls.

> **Warning** 🚧 Work in progress

## Usage

1. Update `blocklist-generator.toml` with host and domain blocklists, also add
   any allowed overrides.
2. Add any extra blocked names to `blocked-names.txt`.
3. Run the app

   ```console
   ./blocklist-generator
   ```

4. Use generated blocklist files:
   - domain-blocklist.txt
   - blocklist.rpz

## License

The project is licensed under BSD 3-Clause License — see the
[LICENSE](./LICENSE) file for details.
