import re, unicodedata, pycountry, geonamescache

REGIONS = """
HK ap-east-1 asia-east2 eastasia TW ap-east-2 asia-east1 IN ap-south-1 ap-south-2
asia-south1 asia-south2 JP ap-northeast-1 ap-northeast-3 asia-northeast1 asia-northeast2
KR ap-northeast-2 asia-northeast3 SG ap-southeast-1 asia-southeast1 southeastasia AU
ap-southeast-2 ap-southeast-4 ID ap-southeast-3 asia-southeast2 MY ap-southeast-5 NZ
ap-southeast-6 TH ap-southeast-7 asia-southeast3 DE eu-central-1 europe-west3
europe-west10 europe-west15 eusc CH eu-central-2 europe-west6 IE eu-west-1 northeurope GB
eu-west-2 europe-west2 uk FR eu-west-3 europe-west9 IT eu-south-1 europe-west8
europe-west12 ES eu-south-2 europe-southwest1 SE eu-north-1 europe-north2 BH me-south-1
AE me-central-1 uae IL me-west-1 me-west1 BE europe-west1 NL europe-west4 westeurope PL
europe-central2 FI europe-north1 QA me-central1 SA me-central2 CL sa-west-1
southamerica-west1 MX northamerica-south1 queretaro US global boardman CA northamerica ZA
af africa BR sa southamerica vinhedo RS jovanovac"""

REGION_COUNTRY: dict[str, str] = {}
country_code = ""
for token in REGIONS.split():
    if token.isupper():
        country_code = token
    else:
        REGION_COUNTRY[token] = country_code

CARDINALS = ("northeast", "northwest", "southeast", "southwest",
             "north", "south", "east", "west", "central")

ISO_CODES: set[str] = {country.alpha_2 for country in pycountry.countries}

CITIES: list[dict] = sorted(geonamescache.GeonamesCache().get_cities().values(),
                            key=lambda city: -city["population"])


def normalize(value: str) -> str:
    ascii_value = unicodedata.normalize("NFKD", value).encode("ascii", "ignore").decode()
    return re.sub(r"[^a-z0-9]", "", ascii_value.lower())


COUNTRY_NAMES: dict[str, str] = {
    normalize(getattr(country, attribute)): country.alpha_2
    for country in pycountry.countries
    for attribute in ("name", "official_name", "common_name")
    if getattr(country, attribute, None)
}


def strip_cardinals(token: str) -> str:
    for word in CARDINALS:
        if token != word:
            token = re.sub(rf"\d+$|^{word}|{word}$", "", token)
    return token


def by_country_name(token: str) -> str | None:
    return next((code for name, code in COUNTRY_NAMES.items()
                 if len(name) >= 4 and (name in token or token in name)), None)


def by_city_name(token: str) -> str | None:
    return next((city["countrycode"] for city in CITIES
                 if normalize(city["name"]).startswith(token)
                 or token.startswith(normalize(city["name"]))), None)


def resolve(token: str) -> str | None:
    if token in REGION_COUNTRY:
        return REGION_COUNTRY[token]
    if token in CARDINALS or len(token) < 3:
        return None
    return by_country_name(token) or by_city_name(token)


def country(region: str) -> str | None:
    key = region.lower()
    if key in REGION_COUNTRY:
        return REGION_COUNTRY[key]

    fallback = None
    for part in filter(None, key.split("-")):
        for candidate in (part, strip_cardinals(part)):
            matched = resolve(candidate)
            if matched:
                return matched
            if len(candidate) == 2 and candidate.upper() in ISO_CODES:
                fallback = fallback or candidate.upper()
    return fallback
