"""Build the bundled political overlay from Natural Earth v5.1.2 GeoJSON."""
import json
from pathlib import Path
import urllib.request

VERSION = "v5.1.2"
ROOT = Path(__file__).resolve().parent


def read(name):
    filename = name + ".geojson"
    urls = [f"https://raw.githubusercontent.com/nvkelso/natural-earth-vector/{VERSION}/geojson/{filename}",
            f"https://cdn.jsdelivr.net/gh/nvkelso/natural-earth-vector@{VERSION}/geojson/{filename}"]
    for url in urls:
        try:
            with urllib.request.urlopen(url, timeout=30) as response:
                return json.load(response)["features"]
        except Exception as error:
            last = error
    raise last


def build(countries, places):
    output = {"source": "Natural Earth", "version": VERSION, "countries": [], "cities": []}
    for feature in countries:
        properties, geometry = feature["properties"], feature["geometry"]
        polygons = geometry["coordinates"] if geometry["type"] == "MultiPolygon" else [geometry["coordinates"]]
        borders = []
        for polygon in polygons:
            ring = []
            for lon, lat, *_ in polygon[0]:
                point = [round(lon, 3), round(lat, 3)]
                if not ring or point != ring[-1]:
                    ring.append(point)
            if len(ring) > 2:
                borders.append(ring)
        output["countries"].append({"name": properties.get("NAME_RU") or properties["NAME"],
                                    "lon": properties["LABEL_X"], "lat": properties["LABEL_Y"],
                                    "rank": properties["LABELRANK"], "borders": borders})
    for feature in places:
        properties = feature["properties"]
        population, capital = int(properties.get("POP_MAX") or 0), bool(properties.get("ADM0CAP"))
        if population < 500000 and not capital:
            continue
        lon, lat, *_ = feature["geometry"]["coordinates"]
        output["cities"].append({"name": properties.get("NAME_RU") or properties["NAME"],
                                 "lon": round(lon, 4), "lat": round(lat, 4), "population": population, "capital": capital})
    output["cities"].sort(key=lambda p: -p["population"])
    (ROOT / "geography.json").write_text(json.dumps(output, ensure_ascii=False, separators=(",", ":")), encoding="utf-8")
    print(f"Bundled {len(output['countries'])} countries and {len(output['cities'])} cities")


if __name__ == "__main__":
    build(read("ne_50m_admin_0_countries"), read("ne_50m_populated_places"))
