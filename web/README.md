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

## Boundaries and place names

`geography.json` is bundled separately and served through the authenticated
`/assets/geography.json` endpoint. It contains country outlines and Russian
country/city names from [Natural Earth v5.1.2](https://github.com/nvkelso/natural-earth-vector/tree/v5.1.2/geojson)
(`ne_50m_admin_0_countries` and `ne_50m_populated_places`). Natural Earth data is
[public domain](https://www.naturalearthdata.com/about/terms-of-use/).

Rebuild with `python web/build_geography.py`. The builder keeps exterior country
rings with coordinates rounded to 0.001 degree, country label locations and ranks,
and populated places with at least 500,000 people or national-capital status.
It prefers Russian names and falls back to the source name. Population is used
only to rank map labels, not as current demographic information. The source
GeoJSON is fetched from the pinned GitHub tag, with jsDelivr as a mirror fallback.

The overlay works offline on both base maps, is enabled initially, and can be
toggled with **Границы и названия**. Its browser preference is saved independently
of imagery choice. Labels are filtered by zoom, globe occlusion and screen
collisions, with node and RTT labels taking priority. The overlay uses a separate
Cesium data source so live node updates do not remove country boundaries.
