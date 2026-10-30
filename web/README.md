# Globe assets

`cesium.zip` contains the unmodified `Build/Cesium/` files from the official
[CesiumJS 1.146.0 npm package](https://registry.npmjs.org/cesium/-/cesium-1.146.0.tgz),
plus the package's `LICENSE.md` and `ThirdParty.extra.json`. Source maps are omitted.
The archive includes Cesium's bundled Natural Earth II imagery, workers and widgets.
It is embedded in the .NET executable and served through the authenticated
`/assets/cesium/` endpoint. No separate frontend install or build is needed.

Archive SHA-256: `bd85b84b431b691ec1d03705666a94b7269d93dfb97bf408459a98c055fcf982`.

CesiumJS is licensed under Apache-2.0. The distributed license and third-party
notices are retained in the archive, and Cesium's on-screen credits remain visible.

Run backend checks with `dotnet run --project tests/WebChecks -c Release`.
For browser checks, start the same command with `-- --serve`, then run
`node tests/WebChecks/browser.cjs <printed-BROWSER_URL>` with Playwright available
via `NODE_PATH` and Google Chrome installed. The browser check blocks external
requests to verify that the globe renders with local assets only. It uses isolated
test identities, manual test coordinates, a random HTTPS port and temporary data.
